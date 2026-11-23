package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// askKeyHistory is GET /publickey/history of g, by its status and body.

// edPin pins key as an Ed25519 key.
func edPin(key []byte) *heldKey {
	pin := edKey(key)
	return &pin
}
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
	entries, err := checkKeyHistory(body, edPin(pinned))
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
	if _, err := checkKeyHistory(body, edPin(one.publicKey())); err == nil {
		t.Fatal("a history held from a key it does not begin at")
	}
}

// Two rotations in one second, as two SIGHUPs back to back make them, are
// written and walked, and the history the gateway serves for them holds:
// it is answered 200, by the consumer's check too, not 500 for good.
func TestTwoRotationsInOneSecondServeAHistoryThatHolds(t *testing.T) {
	standInKeyService(t)
	one, two := mustKeyServiceSigner(t, ksVersion1), mustKeyServiceSigner(t, ksVersion2)
	g, _, _ := ksService(t, nil)
	seedKey := seedKeyOf(testSeed)
	at := "2026-11-19T00:00:00Z"
	if _, err := g.registry.rotateTo(one, at); err != nil {
		t.Fatal(err)
	}
	if _, err := g.registry.rotateTo(two, at); err != nil {
		t.Fatal(err)
	}
	if code, body := askKeyHistory(t, g); code != http.StatusOK {
		t.Fatalf("two rotations in one second: %d %s", code, body)
	}
	entries, _ := historyPinned(t, g, seedKey)
	wantKeys(t, entries, []ed25519.PublicKey{seedKey, one.publicKey(), two.publicKey()}, []string{at, at})
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
	entries, err := registryKeyHistory(data, edKey(third.Public().(ed25519.PublicKey)), nil, false)
	if err != nil {
		t.Fatal(err)
	}
	doc := keyHistoryDocument(entries)
	pinned := first.Public().(ed25519.PublicKey)
	if _, err := checkKeyHistory(doc, edPin(pinned)); err != nil {
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
		if _, err := checkKeyHistory(out, edPin(pinned)); err == nil {
			t.Errorf("%s: the check passed\n%s", name, out)
		}
	}
	if _, err := checkKeyHistory(doc, edPin(second.Public().(ed25519.PublicKey))); err == nil {
		t.Error("a history held from a key it does not begin at")
	}
}

// A store rotation carries the key history into the new store: the new
// store's gateway answers the old store's history, the key in force at the
// rotation its last entry; a rotation in the new store, whose ordinals start
// again at 1, ends that key; a second store rotation carries the whole
// history on. The carried history is the one the store continuation names
// by its digest: one changed, one cut to a later stretch that holds on its
// own, and one deleted are each answered 500, never as a shorter history,
// and the history named is answered again once it is back; one carried
// beside no store continuation is answered 500 too.
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
	// cut to a later stretch: from the second key on, which holds on its own
	// and ends at the key that signed the continuation
	whole, err := checkKeyHistory(after, nil)
	if err != nil {
		t.Fatal(err)
	}
	stretch := slices.Clone(whole[1:])
	stretch[0].validFrom, stretch[0].forward, stretch[0].reverse = "", "", ""
	cut := keyHistoryDocument(stretch)
	if held, err := checkKeyHistory(cut, edPin(keys[1])); err != nil || len(held) != 2 {
		t.Fatalf("the stretch does not hold on its own: %v", err)
	}
	if err := os.WriteFile(carried, cut, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, body := askKeyHistory(t, g3); code != http.StatusInternalServerError {
		t.Fatalf("a carried history cut to a later stretch: %d %s", code, body)
	}
	if err := os.Remove(carried); err != nil {
		t.Fatal(err)
	}
	if code, body := askKeyHistory(t, g3); code != http.StatusInternalServerError || string(body) != `{"error":"the key history could not be read; the gateway says why on its stderr"}` {
		t.Fatalf("a continued store whose carried history is deleted: %d %s", code, body)
	}
	if err := os.WriteFile(carried, after, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, back := historyPinned(t, g3, keys[0]); !bytes.Equal(back, after) {
		t.Fatalf("the history named, back beside the registry, is not answered:\n%s", back)
	}
	if err := os.WriteFile(keyHistoryBeside(g.regPath), before, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, body := askKeyHistory(t, g); code != http.StatusInternalServerError {
		t.Fatalf("a history carried beside a registry that continues no store: %d %s", code, body)
	}
}

// A store rotation stopped after its new registry was made and before its
// mark is finished by a rerun, which carries the key history again where
// none is beside the new registry, and the history it carries is the old
// store's, the one the continuation names.
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

// A rerun of a store rotation holds a key history beside the new registry to
// the one its store continuation names: one changed since -- here cut to the
// key in force, a history that holds on its own -- refuses the rerun, which
// changes nothing, the old store left unmarked and the history as it was.
func TestARerunOfAStoreRotationRefusesAKeyHistoryNotTheOneNamed(t *testing.T) {
	g, _, _ := ksService(t, nil)
	seed2 := historySeed("2")
	if _, err := g.registry.rotateTo(newSeedSigner(seed2), "2026-11-19T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	newStore, newRegistry := filepath.Join(dir, "store"), filepath.Join(dir, "registry.jsonl")
	seedPath := writeSeedFile(t, t.TempDir(), seed2)
	if code, stdout, stderr := rotateOn(t, g, seedPath, newStore, newRegistry, "2026-11-19T00:00:01Z"); code != 0 {
		t.Fatalf("store rotate: %d %s %s", code, stdout, stderr)
	}
	if err := os.Remove(rotatedMarkPath(g.regPath)); err != nil {
		t.Fatal(err)
	}
	key := seedKeyOf(seed2)
	changed := keyHistoryDocument([]keyHistoryEntry{{key: key, keyID: keyIDFor(key)}})
	if err := os.WriteFile(keyHistoryBeside(newRegistry), changed, 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := rotateOn(t, g, seedPath, newStore, newRegistry, "2026-11-19T00:00:02Z")
	if code == 0 || !strings.Contains(stderr, "its store continuation names; nothing was changed") {
		t.Fatalf("a rerun over a key history not the one named: %d %s %s", code, stdout, stderr)
	}
	if _, err := os.Lstat(rotatedMarkPath(g.regPath)); !absent(err) {
		t.Fatalf("the refused rerun marked the old store: %v", err)
	}
	if got := readFile(t, keyHistoryBeside(newRegistry)); got != string(changed) {
		t.Fatalf("the refused rerun changed the key history:\n%s", got)
	}
}

// A carried history that holds, and whose bytes are the ones the store
// continuation names, must still end at the key that signed the
// continuation: one ending at another key is answered 500, and the same
// store with a history ending at that key is answered.
func TestACarriedKeyHistoryEndsAtTheKeyThatSignedTheContinuation(t *testing.T) {
	signer := ed25519.NewKeyFromSeed(testSeed)
	serveWith := func(ending ed25519.PublicKey) (int, []byte) {
		dir := t.TempDir()
		newStore, newRegistry := filepath.Join(dir, "store"), filepath.Join(dir, "registry.jsonl")
		if err := os.Mkdir(newStore, 0o700); err != nil {
			t.Fatal(err)
		}
		history := keyHistoryDocument([]keyHistoryEntry{{key: ending, keyID: keyIDFor(ending)}})
		if _, err := checkKeyHistory(history, edPin(ending)); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyHistoryBeside(newRegistry), history, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(newRegistry, seedContinuation(t, signer, []byte("x\n"), history, "2026-11-19T00:00:00Z"), 0o600); err != nil {
			t.Fatal(err)
		}
		g, err := newGatewayServiceSigned(newStore, testSeed, nil, "gateway:test", newRegistry, ksSources())
		if err != nil {
			t.Fatal(err)
		}
		return askKeyHistory(t, g)
	}
	if code, body := serveWith(seedKeyOf(historySeed("other"))); code != http.StatusInternalServerError {
		t.Fatalf("a carried history ending at another key: %d %s", code, body)
	}
	if code, body := serveWith(seedKeyOf(testSeed)); code != http.StatusOK {
		t.Fatalf("a carried history ending at the key that signed the continuation: %d %s", code, body)
	}
}

// A history that does not hold is walked once per change of what it is made
// of: two requests to a registry with a forged rotation are one walk, both
// answered 500; the registry changed is walked again.
func TestAKeyHistoryThatDoesNotHoldIsWalkedOncePerChange(t *testing.T) {
	g, _, registry := ksService(t, nil)
	mustAcquire(t, g, "a")
	mustSeal(t, g, "a")
	data, err := os.ReadFile(registry)
	if err != nil {
		t.Fatal(err)
	}
	forged := rotationRecord(data, 1, "2026-11-19T00:00:00Z", ed25519.NewKeyFromSeed(historySeed("other")), ed25519.NewKeyFromSeed(historySeed("next")))
	if err := os.WriteFile(registry, append(bytes.Clone(data), forged...), 0o600); err != nil {
		t.Fatal(err)
	}
	walks := func() int {
		g.keyHistoryKept.mu.Lock()
		defer g.keyHistoryKept.mu.Unlock()
		return g.keyHistoryKept.walks
	}
	before := walks()
	for i := 0; i < 2; i++ {
		if code, body := askKeyHistory(t, g); code != http.StatusInternalServerError {
			t.Fatalf("request %d: a history past a forged rotation: %d %s", i, code, body)
		}
	}
	if got := walks() - before; got != 1 {
		t.Fatalf("two requests to one registry that does not hold made %d walks, not 1", got)
	}
	other := rotationRecord(data, 1, "2026-11-19T00:00:00Z", ed25519.NewKeyFromSeed(historySeed("another")), ed25519.NewKeyFromSeed(historySeed("next")))
	if err := os.WriteFile(registry, append(bytes.Clone(data), other...), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _ := askKeyHistory(t, g); code != http.StatusInternalServerError {
		t.Fatalf("a history past another forged rotation: %d", code)
	}
	if got := walks() - before; got != 2 {
		t.Fatalf("a changed registry made %d walks in all, not 2", got)
	}
	// the registry as it was holds again, and is answered
	if err := os.WriteFile(registry, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, body := askKeyHistory(t, g); code != http.StatusOK {
		t.Fatalf("the registry restored: %d %s", code, body)
	}
}

// The rotatedAt of each rotation in a history is not before the one before
// it: a chain whose second rotation is before the first holds signature by
// signature and is refused by the check all the same; one of the first's
// second holds, since the writers make it.
func TestTheKeyHistoryCheckRefusesARotationBeforeTheOneBefore(t *testing.T) {
	first, second, third := ed25519.NewKeyFromSeed(historySeed("1")), ed25519.NewKeyFromSeed(historySeed("2")), ed25519.NewKeyFromSeed(historySeed("3"))
	for _, at := range []string{"2026-11-19T00:00:01Z", "2026-11-19T00:00:00Z", "2026-11-19T00:00:02Z"} {
		data := rotationRecord(nil, 1, "2026-11-19T00:00:01Z", first, second)
		data = append(data, rotationRecord(data, 2, at, second, third)...)
		entries, err := registryKeyHistory(data, edKey(third.Public().(ed25519.PublicKey)), nil, false)
		if err != nil {
			t.Fatal(err)
		}
		_, err = checkKeyHistory(keyHistoryDocument(entries), edPin(first.Public().(ed25519.PublicKey)))
		want := "entry 2: the rotation's rotatedAt is before the rotatedAt of the rotation before it"
		if at != "2026-11-19T00:00:00Z" {
			if err != nil {
				t.Errorf("a rotation after the one before it: %v", err)
			}
		} else if err == nil || err.Error() != want {
			t.Errorf("a second rotation at %s: %v", at, err)
		}
	}
}

// A store continuation is made while the key in force at the store rotation
// is: its continuedAt at or after that key's validFrom in the history
// carried, and not after the new registry's first rotation from it, if any.
func TestAStoreContinuationIsMadeWhileTheKeyItCarriesIsInForce(t *testing.T) {
	first, second, third := ed25519.NewKeyFromSeed(historySeed("1")), ed25519.NewKeyFromSeed(historySeed("2")), ed25519.NewKeyFromSeed(historySeed("3"))
	old := rotationRecord(nil, 1, "2026-11-19T00:00:05Z", first, second)
	entries, err := registryKeyHistory(old, edKey(second.Public().(ed25519.PublicKey)), nil, false)
	if err != nil {
		t.Fatal(err)
	}
	history := keyHistoryDocument(entries)
	continued := func(at, rotatedAt string) ([]keyHistoryEntry, error) {
		data := seedContinuation(t, second, old, history, at)
		own := second.Public().(ed25519.PublicKey)
		if rotatedAt != "" {
			data = append(data, rotationRecord(data, 1, rotatedAt, second, third)...)
			own = third.Public().(ed25519.PublicKey)
		}
		return registryKeyHistory(data, edKey(own), history, true)
	}
	before := "the store continuation's continuedAt is before the validFrom of the key in force at the store rotation"
	after := "the store continuation's continuedAt is after the validTo of the key in force at the store rotation"
	for _, c := range []struct{ at, rotatedAt, want string }{
		{"2026-11-19T00:00:04Z", "", before},
		{"2026-11-19T00:00:05Z", "", ""},
		{"2026-11-19T00:00:06Z", "2026-11-19T00:00:06Z", ""},
		{"2026-11-19T00:00:07Z", "2026-11-19T00:00:06Z", after},
		{"2026-11-19T00:00:06Z", "2026-11-19T00:00:07Z", ""},
	} {
		_, err := continued(c.at, c.rotatedAt)
		if c.want == "" && err != nil || c.want != "" && (err == nil || err.Error() != c.want) {
			t.Errorf("continued at %s, rotated from at %q: %v, not %q", c.at, c.rotatedAt, err, c.want)
		}
	}
}

// clockBehind is the refusal of a rotation stamped at before the key
// history's last rotation last.
func clockBehind(at, last string) string {
	return "the rotation's rotatedAt " + at + " is before the key history's last rotation " + last + "; correct this host's clock and run again; nothing was written"
}

// Every writer's record is held to the key history before it is written
// (keyHistoryWriteRefusal): a stamp before the last rotation is the clock,
// said as such; any other finding of the history with the record is the
// record's; two of one second hold.
func TestAWritersRecordIsHeldToTheKeyHistoryOneCauseEach(t *testing.T) {
	before := []keyHistoryEntry{{keyID: "a", validTo: "2026-11-19T00:00:05Z"}, {keyID: "b", validFrom: "2026-11-19T00:00:05Z"}}
	found := errors.New("the walk's finding")
	fails := func() error { return found }
	if err := keyHistoryWriteRefusal(before, "2026-11-19T00:00:04Z", storeRotateKeyBefore, keyHistoryRotationFault, fails); err == nil || err.Error() != clockBehind("2026-11-19T00:00:04Z", "2026-11-19T00:00:05Z") {
		t.Fatalf("a stamp before the last rotation: %v", err)
	}
	if err := keyHistoryWriteRefusal(before, "2026-11-19T00:00:05Z", storeRotateKeyBefore, keyHistoryRotationFault, fails); !errors.Is(err, found) || err.Error() != "the rotation's record would not hold in the key history: the walk's finding" {
		t.Fatalf("a record whose history does not hold for another cause: %v", err)
	}
	if err := keyHistoryWriteRefusal(before, "2026-11-19T00:00:05Z", storeRotateKeyBefore, keyHistoryRotationFault, func() error { return nil }); err != nil {
		t.Fatalf("a stamp in the last rotation's second: %v", err)
	}
	if err := keyHistoryWriteRefusal(before[:1], "2026-11-19T00:00:01Z", storeRotateKeyBefore, keyHistoryRotationFault, nil); err != nil {
		t.Fatalf("a history of no rotation: %v", err)
	}
}

// A rotation while serving (SIGHUP's rotateTo) stamped before the key
// history's last rotation is refused before the append, the registry and
// the key in force unchanged; one in the same second is made, and the
// history it leaves is answered.
func TestARotationWhileServingStampedBeforeTheLastIsRefused(t *testing.T) {
	standInKeyService(t)
	one, two := mustKeyServiceSigner(t, ksVersion1), mustKeyServiceSigner(t, ksVersion2)
	g, _, registry := ksService(t, nil)
	if _, err := g.registry.rotateTo(one, "2026-11-19T00:00:05Z"); err != nil {
		t.Fatal(err)
	}
	before := readFile(t, registry)
	_, err := g.registry.rotateTo(two, "2026-11-19T00:00:04Z")
	if err == nil || err.Error() != clockBehind("2026-11-19T00:00:04Z", "2026-11-19T00:00:05Z") || readFile(t, registry) != before {
		t.Fatalf("a rotation stamped before the last: %v", err)
	}
	if g.publicKeyDocument()["keyId"] != keyIDFor(one.publicKey()) {
		t.Fatal("the refused rotation switched the key")
	}
	if _, err := g.registry.rotateTo(two, "2026-11-19T00:00:05Z"); err != nil {
		t.Fatalf("a rotation in the last one's second: %v", err)
	}
	if code, body := askKeyHistory(t, g); code != http.StatusOK {
		t.Fatalf("the history after: %d %s", code, body)
	}
}

// readsCounted counts the reads of r.
type readsCounted struct {
	r io.Reader
	n int
}

func (c *readsCounted) Read(p []byte) (int, error) {
	c.n++
	return c.r.Read(p)
}

// gateway rotate-key stamped before the key history's last rotation is
// refused before the next seed is made, the registry unchanged and nothing
// left beside the seed; one in the same second is made.
func TestRotateKeyStampedBeforeTheLastRotationIsRefused(t *testing.T) {
	root := t.TempDir()
	seedPath, registry := filepath.Join(root, "gateway.seed"), filepath.Join(root, "registry.jsonl")
	writeTestSeed(t, seedPath, testSeed)
	if _, err := newGatewayService(filepath.Join(root, "store"), testSeed, "gateway:test", registry, map[string]sourceSpec{}); err != nil {
		t.Fatal(err)
	}
	if _, err := rotateKey(seedPath, registry, fixedStamp("2026-10-25T00:00:05Z"), rand.Reader); err != nil {
		t.Fatal(err)
	}
	before := readFile(t, registry)
	read := &readsCounted{r: rand.Reader}
	_, err := rotateKey(seedPath, registry, fixedStamp("2026-10-25T00:00:04Z"), read)
	if err == nil || err.Error() != clockBehind("2026-10-25T00:00:04Z", "2026-10-25T00:00:05Z") || readFile(t, registry) != before {
		t.Fatalf("a rotation stamped before the last: %v", err)
	}
	if read.n != 0 {
		t.Fatal("the refused rotation made a next seed")
	}
	for _, left := range []string{seedPath + nextSeedSuffix, seedPath + recordSuffix, seedPath + ".rotated-2"} {
		if exists(left) {
			t.Fatalf("the refused rotation left %s", left)
		}
	}
	if _, err := rotateKey(seedPath, registry, fixedStamp("2026-10-25T00:00:05Z"), rand.Reader); err != nil {
		t.Fatalf("a rotation in the last one's second: %v", err)
	}
}

// gateway store rotate whose continuation is stamped before the last
// rotation of the history it carries is refused before anything is sealed
// or written: the old registry unchanged, an open session left open, and
// no new store. One in the same second rotates, and a rotation of the new
// store stamped before that rotation is refused in its turn.
func TestAStoreRotationStampedBeforeTheLastRotationIsRefused(t *testing.T) {
	g, _, registry := ksService(t, nil)
	seed2, seed3 := historySeed("2"), historySeed("3")
	if _, err := g.registry.rotateTo(newSeedSigner(seed2), "2026-11-19T00:00:05Z"); err != nil {
		t.Fatal(err)
	}
	mustAcquire(t, g, "left-open")
	before := readFile(t, registry)
	dir := t.TempDir()
	newStore, newRegistry := filepath.Join(dir, "store"), filepath.Join(dir, "registry.jsonl")
	seedFile := writeSeedFile(t, t.TempDir(), seed2)
	code, stdout, stderr := rotateOn(t, g, seedFile, newStore, newRegistry, "2026-11-19T00:00:04Z")
	want := "the store continuation's continuedAt 2026-11-19T00:00:04Z is before the key history's last rotation 2026-11-19T00:00:05Z; correct this host's clock and run again; nothing was written"
	if code != 1 || !strings.Contains(stderr, want) || readFile(t, registry) != before || exists(newStore) || exists(newRegistry) {
		t.Fatalf("a store rotation stamped before the last: %d %q %q", code, stdout, stderr)
	}
	if code, stdout, stderr := rotateOn(t, g, seedFile, newStore, newRegistry, "2026-11-19T00:00:05Z"); code != 0 {
		t.Fatalf("a store rotation in the last one's second: %d %q %q", code, stdout, stderr)
	}
	g2, err := newGatewayServiceSigned(newStore, seed2, nil, "gateway:test", newRegistry, ksSources())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g2.registry.rotateTo(newSeedSigner(seed3), "2026-11-19T00:00:04Z"); err == nil || err.Error() != clockBehind("2026-11-19T00:00:04Z", "2026-11-19T00:00:05Z") {
		t.Fatalf("a rotation of the new store stamped before the carried last: %v", err)
	}
	if code, body := askKeyHistory(t, g2); code != http.StatusOK {
		t.Fatalf("the new store's history: %d %s", code, body)
	}
}
