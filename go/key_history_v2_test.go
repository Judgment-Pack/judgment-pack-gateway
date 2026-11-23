package main

// The key history of version 2 (SPEC.md §3e; ADR-0055): the corpus family
// in process, and the gateway's answers of both versions held to the bytes
// the family's independent generator made.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// corpusRotationKey is the corpus rotation key i: its seed the SHA-256 of
// the published text ending in i (corpus/README.md).
func corpusRotationKey(i int) heldKey {
	seed := sha256.Sum256([]byte(fmt.Sprintf("judgment-pack-gateway corpus rotation key %d", i)))
	return edKey(ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey))
}

// khVector is a key-history vector's history, as bytes and parsed.
func khVector(t *testing.T, name string) (string, *vObject) {
	t.Helper()
	v, err := readKeyHistoryVector(filepath.Join("..", "corpus", "key-history", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseJSON([]byte(v.History))
	if err != nil {
		t.Fatal(err)
	}
	return v.History, parsed.(*vObject)
}

func khMember(t *testing.T, v value, names ...string) value {
	t.Helper()
	for _, name := range names {
		obj, ok := v.(*vObject)
		if !ok {
			t.Fatalf("not an object at %s", name)
		}
		if v, ok = obj.get(name); !ok {
			t.Fatalf("no member %s", name)
		}
	}
	return v
}

// khStore is store j of a version 2 history.
func khStore(t *testing.T, obj *vObject, j int) *vObject {
	t.Helper()
	return khMember(t, obj, "stores").(vArray)[j].(*vObject)
}

// khRotationLines are the registry lines of the rotation to entry i of a
// list of keys, as the registry holds them.
func khRotationLines(t *testing.T, keys value, i int) string {
	t.Helper()
	entry := keys.(vArray)[i]
	return string(khMember(t, entry, "keyRotation").(vString)) + "\n" + string(khMember(t, entry, "keyContinuation").(vString)) + "\n"
}

// khBefore is the history before store j of a history without base:
// canon of {keyHistoryVersion: "2", stores: the stores before it}.
func khBefore(t *testing.T, obj *vObject, j int) []byte {
	t.Helper()
	return historyBefore(nil, false, khMember(t, obj, "stores").(vArray)[:j])
}

func TestKeyHistoryVectorsHoldInProcess(t *testing.T) {
	failures, n, err := runKeyHistoryVectors(filepath.Join("..", "corpus"))
	if err != nil {
		t.Fatal(err)
	}
	if n != 29 || len(failures) != 0 {
		t.Fatalf("%d key-history vectors, disagreements %q", n, failures)
	}
}

// With the member absent a gateway answers version 1, byte for byte the
// generator's: of a registry of one rotation, and of a store continued with
// a version 1 history carried, whose ordinal starts again at 1. Under "2"
// the same registry and history answer kh-v2-base, the carried bytes as base.
func TestAKeyHistoryOfVersion1IsTheSameBytesWithTheMemberAbsent(t *testing.T) {
	want2, v2 := khVector(t, "kh-v2-base")
	base := canon(khMember(t, v2, "base"))
	doc, err := walkKeyHistory([]byte(khRotationLines(t, khMember(t, v2, "base", "keys"), 1)), corpusRotationKey(1), nil, false, "")
	if err != nil || string(doc) != string(base) {
		t.Fatalf("a registry of one rotation: %v\n%s\nwant %s", err, doc, base)
	}
	store := khStore(t, v2, 0)
	registry := []byte(string(khMember(t, store, "continuation").(vString)) + "\n" + khRotationLines(t, khMember(t, store, "keys"), 1))
	want1, _ := khVector(t, "kh-v1-ordinal-given-twice")
	if doc, err := walkKeyHistory(registry, corpusRotationKey(2), base, true, ""); err != nil || string(doc) != want1 {
		t.Fatalf("a continued store under version 1: %v\n%s", err, doc)
	}
	if doc, err := walkKeyHistory(registry, corpusRotationKey(2), base, true, keyHistoryVersion2); err != nil || string(doc) != want2 {
		t.Fatalf("a continued store under version 2: %v\n%s", err, doc)
	}
}

// Version 2 from the gateway: one store for no carried history; a carried
// version 2 history's stores, then its own, with the member absent (the
// sticky rule); and across a P-256 boundary.
func TestAKeyHistoryOfVersion2IsTheGeneratorsBytes(t *testing.T) {
	want, one := khVector(t, "kh-v2-one-store")
	keys := khMember(t, khStore(t, one, 0), "keys")
	registry := khRotationLines(t, keys, 1) + khRotationLines(t, keys, 2)
	if doc, err := walkKeyHistory([]byte(registry), corpusRotationKey(2), nil, false, keyHistoryVersion2); err != nil || string(doc) != want {
		t.Fatalf("one store: %v\n%s", err, doc)
	}
	if doc, err := walkKeyHistory([]byte(registry), corpusRotationKey(2), nil, false, ""); err != nil || !strings.HasPrefix(string(doc), `{"keyHistoryVersion":"1",`) {
		t.Fatalf("one store, the member absent: %v\n%s", err, doc)
	}

	want, across := khVector(t, "kh-v2-across-store")
	store := khStore(t, across, 1)
	registry = string(khMember(t, store, "continuation").(vString)) + "\n" + khRotationLines(t, khMember(t, store, "keys"), 1)
	if doc, err := walkKeyHistory([]byte(registry), corpusRotationKey(2), khBefore(t, across, 1), true, ""); err != nil || string(doc) != want {
		t.Fatalf("a carried version 2 history, the member absent: %v\n%s", err, doc)
	}

	want, p256 := khVector(t, "kh-v2-p256-continuation")
	text, err := os.ReadFile(filepath.Join("..", "corpus", "TEST-P256-PUBLIC-KEY"))
	if err != nil {
		t.Fatal(err)
	}
	point, _ := hex.DecodeString(strings.TrimSpace(string(text)))
	p := heldKey{alg: algES256, key: point}
	line := string(khMember(t, khStore(t, p256, 1), "continuation").(vString)) + "\n"
	made, err := registryKeyHistoryOf([]byte(line), p, khBefore(t, p256, 1), true, "")
	if err != nil || string(made.doc) != want || len(made.entries) != 2 || made.last != "2026-08-01T02:00:00Z" {
		t.Fatalf("across a P-256 boundary: %v, last %q\n%s", err, made.last, made.doc)
	}
	// the history's last time is its last continuedAt: a store rotation
	// stamped before it is the clock's, said as such
	at := "2026-08-01T01:30:00Z"
	if err := continuationOrderRefusalOf([]byte(line), p, khBefore(t, p256, 1), true, at, ""); err == nil || err.Error() != fmt.Sprintf(keyHistoryContinuationOrder, at, "2026-08-01T02:00:00Z") {
		t.Fatalf("a store rotation before the last continuedAt: %v", err)
	}
}

// A carried version 1 history that is not canon of its value is answered as
// version 1, as before, and refused under version 2, whose base would not be
// the bytes carried: the route answers 500.
func TestACarriedHistoryThatIsNotCanonIsNotAnsweredAsBase(t *testing.T) {
	_, v2 := khVector(t, "kh-v2-base")
	carried := []byte(`{"keys":` + string(canon(khMember(t, v2, "base", "keys"))) + `,"keyHistoryVersion":"1"}`)
	seed := sha256.Sum256([]byte("judgment-pack-gateway corpus rotation key 1"))
	line := seedContinuation(t, ed25519.NewKeyFromSeed(seed[:]), []byte("{}\n"), carried, "2026-08-01T02:00:00Z")
	registry := append(line, khRotationLines(t, khMember(t, khStore(t, v2, 0), "keys"), 1)...)
	want1, _ := khVector(t, "kh-v1-ordinal-given-twice")
	if doc, err := walkKeyHistory(registry, corpusRotationKey(2), carried, true, ""); err != nil || string(doc) != want1 {
		t.Fatalf("under version 1: %v\n%s", err, doc)
	}
	if _, err := walkKeyHistory(registry, corpusRotationKey(2), carried, true, keyHistoryVersion2); err == nil || !strings.Contains(err.Error(), "not in canon form") {
		t.Fatalf("under version 2: %v", err)
	}
}

// store rotate carries what the old store's gateway answers under the
// rotation's configuration: "2" with the member, by its flags "2" only after
// "2"; and a rerun holds the history to the digest the continuation names.
func TestStoreRotateCarriesVersion2ByTheMemberOrAfterVersion2(t *testing.T) {
	dir := t.TempDir()
	write := func(name, registry string, carried []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(registry), 0o600); err != nil {
			t.Fatal(err)
		}
		if carried != nil {
			if err := os.WriteFile(keyHistoryBeside(path), carried, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return path
	}
	carry := func(path string, own heldKey, configured string) string {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		history, err := carriedHistoryOf(path, data, own, configured)
		if err != nil {
			t.Fatal(err)
		}
		return string(history)
	}
	want2, v2 := khVector(t, "kh-v2-base")
	_, across := khVector(t, "kh-v2-across-store")
	base := canon(khMember(t, v2, "base"))
	fresh := write("fresh.jsonl", khRotationLines(t, khMember(t, v2, "base", "keys"), 1), nil)
	if got := carry(fresh, corpusRotationKey(1), keyHistoryVersion2); got != string(khBefore(t, across, 1)) {
		t.Fatalf("a fresh store with the member: %s", got)
	}
	if got := carry(fresh, corpusRotationKey(1), ""); got != string(base) {
		t.Fatalf("a fresh store by its flags: %s", got)
	}
	store := khStore(t, v2, 0)
	afterV1 := string(khMember(t, store, "continuation").(vString)) + "\n" + khRotationLines(t, khMember(t, store, "keys"), 1)
	continued := write("after-1.jsonl", afterV1, base)
	if want1, _ := khVector(t, "kh-v1-ordinal-given-twice"); carry(continued, corpusRotationKey(2), "") != want1 {
		t.Fatal("by its flags after version 1: not version 1")
	}
	if got := carry(continued, corpusRotationKey(2), keyHistoryVersion2); got != want2 {
		t.Fatalf("with the member after version 1: %s", got)
	}
	wantAcross, _ := khVector(t, "kh-v2-across-store")
	next := khStore(t, across, 1)
	afterV2 := write("after-2.jsonl", string(khMember(t, next, "continuation").(vString))+"\n"+khRotationLines(t, khMember(t, next, "keys"), 1), khBefore(t, across, 1))
	if got := carry(afterV2, corpusRotationKey(2), ""); got != wantAcross {
		t.Fatalf("by its flags after version 2: %s", got)
	}

	// a rerun: the history the continuation names is carried again only
	// under the configuration that made it
	newRegistry := filepath.Join(dir, "new.jsonl")
	data := []byte(afterV1)
	named := keyHistoryDigestOf([]byte(want2))
	if err := carryKeyHistory(continued, data, corpusRotationKey(2), newRegistry, named, ""); err == nil || !strings.Contains(err.Error(), "nothing was changed") {
		t.Fatalf("a rerun by its flags of a version 2 rotation: %v", err)
	}
	if _, err := os.Lstat(keyHistoryBeside(newRegistry)); err == nil {
		t.Fatal("a refused rerun wrote a history")
	}
	if err := carryKeyHistory(continued, data, corpusRotationKey(2), newRegistry, named, keyHistoryVersion2); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, keyHistoryBeside(newRegistry)); got != want2 {
		t.Fatalf("the rerun's history: %s", got)
	}
}

// keyHistoryVersion is a member of engine version keyHistoryV2Version whose
// one value is "2"; below the version, and of any other value, it is refused.
func TestEngineKeyHistoryVersionIsOneValueFromItsVersion(t *testing.T) {
	catalog := catalogWith(t, map[string]string{"postgres": postgresBinding})
	good := platformJSON(t, "warehouse", "postgres@"+digestOf(postgresBinding), "engine-warehouse", ``)
	base := engineJSON(t, catalog, ``, good)
	at := func(version, member string) string {
		return strings.Replace(base, `"engineVersion":"1"`, `"engineVersion":"`+version+`"`+member, 1)
	}
	cfg, err := parseEngineConfig([]byte(at(keyHistoryV2Version, `,"keyHistoryVersion":"2"`)))
	if err != nil || cfg.keyHistoryVersion != keyHistoryVersion2 {
		t.Fatalf("the member at its version: %v, %q", err, cfg.keyHistoryVersion)
	}
	// serve takes its options from engineServeOptions alone (main.go), so the
	// member reaches /publickey/history and a SIGHUP rotation only through it
	if opts := engineServeOptions(cfg, nil, nil); opts.keyHistoryVersion != keyHistoryVersion2 {
		t.Fatalf("the serve options of a configuration that names it: %q", opts.keyHistoryVersion)
	}
	if cfg, err := parseEngineConfig([]byte(at(keyHistoryV2Version, ``))); err != nil || cfg.keyHistoryVersion != "" {
		t.Fatalf("absent: %v, %q", err, cfg.keyHistoryVersion)
	}
	for _, c := range []struct{ version, member, want string }{
		{p256SignerVersion, `,"keyHistoryVersion":"2"`, "engine configuration: keyHistoryVersion is a version-" + keyHistoryV2Version + " member; engineVersion " + p256SignerVersion + " has no keyHistoryVersion"},
		{keyHistoryV2Version, `,"keyHistoryVersion":"1"`, `engine configuration: keyHistoryVersion is "2", or absent`},
		{keyHistoryV2Version, `,"keyHistoryVersion":2`, `engine configuration: keyHistoryVersion is "2", or absent`},
	} {
		if _, err := parseEngineConfig([]byte(at(c.version, c.member))); err == nil || err.Error() != c.want {
			t.Fatalf("%s at %s: %v", c.member, c.version, err)
		}
	}
}
