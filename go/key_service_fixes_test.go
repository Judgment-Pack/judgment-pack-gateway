package main

// The review round of the key-service signer (ADR-0050): the key pinned
// against the history and signingPublicKey, the latch and the lifetime,
// the PostgreSQL kind's lease under the signer's key, the operator
// commands through the signer, and the rotation at SIGHUP.

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const ksStamp = "2026-11-19T00:00:00Z"

func ksStamper() string { return ksStamp }

func ksSources() map[string]sourceSpec {
	return map[string]sourceSpec{"screening": {argv: []string{os.Args[0]}, env: helperEnv}}
}

// A key service's key does not start over history under another key that no
// rotation leads from: a seed-signed registry, or a store holding the seed's
// receipts and no seal; once the rotation is recorded, it starts.
func TestAKeyServiceDoesNotStartOverHistoryUnderAnotherKey(t *testing.T) {
	standInKeyService(t)
	one := mustKeyServiceSigner(t, ksVersion1)
	sealed, store, registry := ksService(t, nil)
	mustAcquire(t, sealed, "seeded")
	mustSeal(t, sealed, "seeded")
	if _, err := newGatewayServiceSigned(store, testSeed, one, "gateway:test", registry, ksSources()); err == nil || !strings.Contains(err.Error(), "the registry holds a record that is under key id "+keyIDFor(ed25519.NewKeyFromSeed(testSeed).Public().(ed25519.PublicKey))) {
		t.Fatalf("a key service started over a seed-signed registry: %v", err)
	}
	open, openStore, openRegistry := ksService(t, nil)
	mustAcquire(t, open, "unsealed")
	if _, err := newGatewayServiceSigned(openStore, testSeed, one, "gateway:test", openRegistry, ksSources()); err == nil || !strings.Contains(err.Error(), "the store holds a receipt that is under key id") {
		t.Fatalf("a key service started over a store of the seed's receipts: %v", err)
	}
	if _, err := sealed.registry.rotateTo(one, ksStamp); err != nil {
		t.Fatal(err)
	}
	if _, err := newGatewayServiceSigned(store, testSeed, one, "gateway:test", registry, ksSources()); err != nil {
		t.Fatalf("the key service did not start once the rotation to it was recorded: %v", err)
	}
}

// signingPublicKey pins the key version's public key: a key version that
// answers another signs nothing, and the refusal names neither key; the
// member is of its form, version 36, and given only beside signingKeyVersion.
func TestSigningPublicKeyPinsTheKeyVersionsKey(t *testing.T) {
	standInKeyService(t)
	one, two := hex.EncodeToString(ksKey("one").Public().(ed25519.PublicKey)), hex.EncodeToString(ksKey("two").Public().(ed25519.PublicKey))
	if _, _, err := newKeyServiceSignerPinned(ksVersion1, two, algEd25519); !errors.Is(err, errKeyServiceNotExpected) || strings.Contains(err.Error(), one) || strings.Contains(err.Error(), two) {
		t.Fatalf("another key version's key: %v", err)
	}
	if _, _, err := newKeyServiceSignerPinned(ksVersion1, one, algEd25519); err != nil {
		t.Fatal(err)
	}
	catalog := catalogWith(t, map[string]string{"records": tokenBinding})
	ref := "records@" + digestOf(tokenBinding)
	adapters := `,"adapters":"` + abs(t, t.TempDir(), "bin") + `"`
	platform := tokenPlatformJSON(t, "records", ref, "engine-docs", ``, ``)
	both := func(key string) string {
		return adapters + `,"signingKeyVersion":"` + ksVersion1 + `","signingPublicKey":"` + key + `"`
	}
	if cfg, _, err := load(t, atVersion(t, keyServiceSignerVersion, catalog, both(one), platform)); err != nil || cfg.signingPublicKey != one {
		t.Fatalf("the member: %v", err)
	}
	if _, _, err := load(t, atVersion(t, keyServiceSignerVersion, catalog, both(strings.ToUpper(one)), platform)); err == nil || !strings.Contains(err.Error(), "64 lowercase hexadecimal") {
		t.Fatalf("out of form: %v", err)
	}
	if _, _, err := load(t, atVersion(t, keyServiceSignerVersion, catalog, adapters+`,"signingPublicKey":"`+one+`"`, platform)); err == nil || !strings.Contains(err.Error(), "not given without it") {
		t.Fatalf("alone: %v", err)
	}
}

// A signing that failed is repeated at once for keyServiceLatch, asking the
// service nothing, and a signing derives from the lifetime bound, so a stop
// ends it.
func TestAFailedSigningLatchesAndAStopEndsASigning(t *testing.T) {
	standIn := standInKeyService(t)
	k := mustKeyServiceSigner(t, ksVersion1)
	standIn.set(func(s *keyServiceStandIn) { s.signStatus = http.StatusServiceUnavailable })
	if _, err := k.sign([]byte("one")); !errors.Is(err, errKeyServiceRefused) {
		t.Fatalf("the first signing: %v", err)
	}
	asked := standIn.requests
	if _, err := k.sign([]byte("two")); !errors.Is(err, errKeyServiceRefused) || standIn.requests != asked {
		t.Fatalf("within the latch the service was asked again: %v, %d requests after %d", err, standIn.requests, asked)
	}
	standIn.set(func(s *keyServiceStandIn) { s.signStatus = 0 })
	k.now = func() time.Time { return time.Now().Add(keyServiceLatch + time.Second) }
	if _, err := k.sign([]byte("three")); err != nil {
		t.Fatalf("after the latch: %v", err)
	}
	stopped := mustKeyServiceSigner(t, ksVersion1)
	life, stop := context.WithCancel(context.Background())
	stop()
	stopped.bindLife(life)
	began := time.Now()
	if _, err := stopped.sign([]byte("four")); !errors.Is(err, errKeyServiceUnreachable) || time.Since(began) > time.Second {
		t.Fatalf("a signing after the stop: %v in %s", err, time.Since(began))
	}
}

// A sign answer naming another version, or an access token out of bounds,
// is not taken.
func TestAnAnswerOutOfBoundsIsNotTaken(t *testing.T) {
	standIn := standInKeyService(t)
	k := mustKeyServiceSigner(t, ksVersion1)
	standIn.set(func(s *keyServiceStandIn) { s.signName = ksVersion2 })
	if _, err := k.sign([]byte("m")); !errors.Is(err, errKeyServiceAnswer) {
		t.Fatalf("an answer naming another version: %v", err)
	}
	for name, body := range map[string]string{
		"a life past a day":   `{"access_token":"` + ksToken + `","expires_in":86401,"token_type":"Bearer"}`,
		"a life of overflow":  `{"access_token":"` + ksToken + `","expires_in":9223372036854775807,"token_type":"Bearer"}`,
		"a token past 16 KiB": `{"access_token":"` + strings.Repeat("a", keyServiceTokenLimit+1) + `","expires_in":3599,"token_type":"Bearer"}`,
		"a token of no form":  `{"access_token":"a b","expires_in":3599,"token_type":"Bearer"}`,
	} {
		standIn.set(func(s *keyServiceStandIn) { s.signName, s.tokenBody = "", "" })
		fresh := mustKeyServiceSigner(t, ksVersion1)
		fresh.token = ""
		standIn.set(func(s *keyServiceStandIn) { s.tokenBody = body })
		if _, err := fresh.accessToken(context.Background()); !errors.Is(err, errKeyServiceToken) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

// On the PostgreSQL kind the lease names the signer's key, the service
// signs through it, and an instance under another key version is refused
// by name, the rolling deploy named.
func TestThePostgreSQLKindSignsThroughTheKeyService(t *testing.T) {
	standInKeyService(t)
	one, two := mustKeyServiceSigner(t, ksVersion1), mustKeyServiceSigner(t, ksVersion2)
	if got := instanceForKey(&storageSpec{several: true}, one.publicKey(), "gateway:test"); got.keyID != keyIDFor(one.publicKey()) {
		t.Fatalf("the lease's key id: %s", got.keyID)
	}
	err := admitBeside(instanceForKey(&storageSpec{several: true}, two.publicKey(), "gateway:test"),
		[]pgLeaseRow{{holder: "instance-serving", keyID: keyIDFor(one.publicKey()), authority: "gateway:test", several: true, live: true}})
	if !errors.Is(err, errInstanceMismatch) || !strings.Contains(err.Error(), "instance-serving") || !strings.Contains(err.Error(), "a rolling deploy that moves the instances to another key version") {
		t.Fatalf("another key version beside the instances serving: %v", err)
	}
	t.Setenv(envSourceHelper, "1")
	g, err := newGatewayServiceOnSigned(newMemoryKind(nil), testSeed, one, "gateway:test", ksSources())
	if err != nil {
		t.Fatal(err)
	}
	mustAcquire(t, g, "kind")
	mustSeal(t, g, "kind")
	if g.store.signing.key().keyID != keyIDFor(one.publicKey()) || g.registry.signing.key().keyID != keyIDFor(one.publicKey()) {
		t.Fatal("the kind's store and registry do not sign under the key service")
	}
	if _, err := g.rotateOnHangup(ksStamper); !errors.Is(err, errRotationOnKind) {
		t.Fatalf("SIGHUP on the kind: %v", err)
	}
}

// SIGHUP on the file kind: signingKeyVersion read again, and the gateway's
// key rotated to it while it serves -- from the seed to the key service,
// and from one key version to the next; a key not signingPublicKey's
// changes nothing.
func TestSIGHUPRotatesTheFileKindToTheConfiguredKeyVersion(t *testing.T) {
	standInKeyService(t)
	g, store, registry := ksService(t, nil)
	mustAcquire(t, g, "seeded")
	reread := engineConfig{signingKeyVersion: ksVersion1, signingPublicKey: hex.EncodeToString(ksKey("two").Public().(ed25519.PublicKey))}
	g.rereadConfig = func() (engineConfig, error) { return reread, nil }
	if _, err := g.rotateOnHangup(ksStamper); !errors.Is(err, errKeyServiceNotExpected) || g.ownKeyID() != keyIDFor(ed25519.NewKeyFromSeed(testSeed).Public().(ed25519.PublicKey)) {
		t.Fatalf("a key version not signingPublicKey's: %v", err)
	}
	reread.signingPublicKey = hex.EncodeToString(ksKey("one").Public().(ed25519.PublicKey))
	if line, err := g.rotateOnHangup(ksStamper); err != nil || !strings.Contains(line, ksVersion1) {
		t.Fatalf("the rotation to the key service: %v", err)
	}
	mustAcquire(t, g, "served")
	reread.signingKeyVersion, reread.signingPublicKey = ksVersion2, hex.EncodeToString(ksKey("two").Public().(ed25519.PublicKey))
	if _, err := g.rotateOnHangup(func() string { return "2026-11-19T00:00:01Z" }); err != nil {
		t.Fatalf("the rotation to the next key version: %v", err)
	}
	mustAcquire(t, g, "after")
	mustSeal(t, g, "seeded")
	mustSeal(t, g, "served")
	mustSeal(t, g, "after")
	rep, err := verifyWithRegistry(store, registry, "gateway:test", ed25519.NewKeyFromSeed(testSeed).Public().(ed25519.PublicKey))
	if err != nil || !rep.OK || rep.Rotations.Count != 2 {
		t.Fatalf("the store after two rotations at SIGHUP: %v %+v", err, rep)
	}
}

// ksCommandStore is a store and registry a key service signs for, with one
// session sealed and, where open, one open, and the seed's file.
func ksCommandStore(t *testing.T, k signer, open bool) (store, registry, seedPath string) {
	t.Helper()
	g, store, registry := ksService(t, k)
	mustAcquire(t, g, "sealed")
	mustSeal(t, g, "sealed")
	if open {
		mustAcquire(t, g, "open")
	}
	seedPath = filepath.Join(t.TempDir(), "seed")
	if err := os.WriteFile(seedPath, testSeed, 0o600); err != nil {
		t.Fatal(err)
	}
	return store, registry, seedPath
}

// gateway seal-open signs through the key service where the configuration
// names it, and refuses the seed given by --seed over that store.
func TestSealOpenSignsThroughTheKeyService(t *testing.T) {
	standInKeyService(t)
	one := mustKeyServiceSigner(t, ksVersion1)
	store, registry, seedPath := ksCommandStore(t, one, true)
	o := sealOpenOptions{store: store, registry: registry, authority: "gateway:test", session: "open", seedNames: []string{seedPath}}
	if _, _, _, err := sealOpen(o, ksStamper); err == nil || !strings.Contains(err.Error(), "no rotation in the registry leads from it") {
		t.Fatalf("the seed over a key service's store: %v", err)
	}
	o.keyVersion = ksVersion1
	sealed, refused, _, err := sealOpen(o, ksStamper)
	if err != nil || len(sealed) != 1 || len(refused) != 0 {
		t.Fatalf("seal-open through the key service: %v %d %v", err, len(sealed), refused)
	}
	if rep, err := verifyWithRegistry(store, registry, "gateway:test", one.publicKey()); err != nil || !rep.OK {
		t.Fatalf("the store after seal-open: %v %+v", err, rep)
	}
}

// gateway remove-artifact signs its removal record through the key service,
// and refuses the seed given by --seed over that store.
func TestRemoveArtifactSignsThroughTheKeyService(t *testing.T) {
	standInKeyService(t)
	one := mustKeyServiceSigner(t, ksVersion1)
	store, registry, seedPath := ksCommandStore(t, one, false)
	o := removeArtifactOptions{store: store, registry: registry, authority: "gateway:test", seedNames: []string{seedPath},
		targets: []removalTarget{{sessionID: "sealed", callIndex: 0}}, by: "operator"}
	if _, _, err := removeArtifact(o, ksStamper); err == nil || !strings.Contains(err.Error(), "no rotation in the registry leads from it") {
		t.Fatalf("the seed over a key service's store: %v", err)
	}
	o.keyVersion = ksVersion1
	out, _, err := removeArtifact(o, ksStamper)
	if err != nil || len(out.appended) != 1 {
		t.Fatalf("remove-artifact through the key service: %v %+v", err, out)
	}
	if keyID, _ := memberString(out.appended[0], "keyId"); keyID != keyIDFor(one.publicKey()) {
		t.Fatalf("the removal record is under key id %s", keyID)
	}
}

// gateway remove-scope signs its records through the key service.
func TestRemoveScopeSignsThroughTheKeyService(t *testing.T) {
	standIn := standInKeyService(t)
	one := mustKeyServiceSigner(t, ksVersion1)
	store, registry, seedPath := ksCommandStore(t, one, false)
	o := removeScopeOptions{store: store, registry: registry, authority: "gateway:test", seedNames: []string{seedPath},
		scope: "scope-unheld", by: "operator", keyVersion: ksVersion1}
	if _, _, err := removeScope(o, ksStamper); err != nil {
		t.Fatalf("remove-scope through the key service: %v", err)
	}
	// the record's signing site, through the key service's key
	asked := standIn.requests
	key := newSigningKey(one)
	record, _, err := signedScopeRemoval(key, []reachedKey{{key: key.public, keyID: key.keyID}}, "scope-unheld", "operator", ksStamp, scopeRemovalCounts{})
	if err != nil || standIn.requests != asked+1 {
		t.Fatalf("a scope removal record through the key service: %v, %d requests after %d", err, standIn.requests, asked)
	}
	if keyID, _ := memberString(record, "keyId"); keyID != key.keyID {
		t.Fatalf("the scope removal record is under key id %s", keyID)
	}
}

// connect's descriptor capture is signed through the key service, and a
// key version not signingPublicKey's signs nothing.
func TestDescriptorCaptureSignsThroughTheKeyService(t *testing.T) {
	standIn := standInKeyService(t)
	one := mustKeyServiceSigner(t, ksVersion1)
	store, _, seedPath := ksCommandStore(t, one, false)
	cfg := engineConfig{store: store, seed: seedPath, authority: "gateway:test", signingKeyVersion: ksVersion1,
		signingPublicKey: hex.EncodeToString(ksKey("two").Public().(ed25519.PublicKey))}
	if _, err := retainConnectedCapture(cfg, []byte(goodSnapshot), "live"); !errors.Is(err, errKeyServiceNotExpected) {
		t.Fatalf("a key version not signingPublicKey's: %v", err)
	}
	cfg.signingPublicKey = ""
	asked := standIn.requests
	if _, err := retainConnectedCapture(cfg, []byte(goodSnapshot), "live"); err != nil || standIn.requests <= asked+1 {
		t.Fatalf("the capture through the key service: %v, %d requests after %d", err, standIn.requests, asked)
	}
}

// gateway retain signs its session-removal records through the key service
// the configuration names, held to signingPublicKey; and with the seed alone
// over that store it is refused before anything is written.
func TestRetainSignsThroughTheKeyService(t *testing.T) {
	standIn := standInKeyService(t)
	one := mustKeyServiceSigner(t, ksVersion1)
	t.Setenv(envSourceHelper, "1")
	root := t.TempDir()
	store, registry := filepath.Join(root, "store"), filepath.Join(root, "registry.jsonl")
	g, err := newGatewayServiceSigned(store, testSeed, one, "gateway:test", registry,
		map[string]sourceSpec{"a": {argv: []string{os.Args[0]}, env: helperEnv, scope: testScope}})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(g.handler())
	if code, out := post(t, server, "/acquire", `{"session":"kept-1","source":"a","scope":`+jsonText(t, testScope)+`,"arguments":{"q":"x"}}`); code != http.StatusOK {
		t.Fatalf("acquire: %d %v", code, out)
	}
	if code, out := post(t, server, "/seal", `{"session":"kept-1","scope":`+jsonText(t, testScope)+`}`); code != http.StatusOK {
		t.Fatalf("seal: %d %v", code, out)
	}
	server.Close()
	seedPath := filepath.Join(t.TempDir(), "seed")
	if err := os.WriteFile(seedPath, testSeed, 0o600); err != nil {
		t.Fatal(err)
	}
	s := sealOf(t, registry, one.publicKey(), "kept-1")
	acks := writeAcks(t, retentionAckLine(retentionAckKey, "kept-1", s.signature, s.finalCount, stampOf(sealTime(t, s))))
	now := sealTime(t, s).Add(31 * 24 * time.Hour)
	config := func(keyService string) string {
		path := filepath.Join(t.TempDir(), "engine.json")
		body := fmt.Sprintf(`{"engineVersion":%q,"authority":"gateway:test","seed":%q,"store":%q,"registry":%q,"decisionRecords":%q,"listen":"127.0.0.1:8787","catalog":%q,"platforms":{}%s,"retention":{"window":30,"acknowledgedBy":[%q]}}`,
			retentionVersion, seedPath, store, registry, filepath.Join(root, "decisions"), filepath.Join(root, "catalog"), keyService,
			hex.EncodeToString(retentionAckKey.Public().(ed25519.PublicKey)))
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	if code, stdout, stderr := runRetain(config(""), acks, now); code != 1 || stdout != "" || !strings.Contains(stderr, "no rotation in the registry leads from it") {
		t.Fatalf("the seed over a key service's store: %d %q %q", code, stdout, stderr)
	}
	if _, err := os.Stat(filepath.Join(store, removalsFile)); !os.IsNotExist(err) {
		t.Fatal("the seed's refusal wrote a removal file")
	}
	asked := standIn.requests
	pinned := fmt.Sprintf(`,"signingKeyVersion":%q,"signingPublicKey":%q`, ksVersion1, hex.EncodeToString(one.publicKey()))
	code, stdout, stderr := runRetain(config(pinned), acks, now)
	if code != 0 || strings.Count(stdout, `"kind":"session-removal"`) != 1 || standIn.requests <= asked {
		t.Fatalf("retain through the key service: %d %q %q, %d requests after %d", code, stdout, stderr, standIn.requests, asked)
	}
	if !strings.Contains(stdout, `"keyId":"`+keyIDFor(one.publicKey())+`"`) {
		t.Fatalf("the removal record is not under the key service's key: %s", stdout)
	}
	if rep, err := verifyWithRegistry(store, registry, "gateway:test", one.publicKey()); err != nil || !rep.OK {
		t.Fatalf("the store after retain: %v %+v", err, rep)
	}
}

// The readiness line names the key in force as it is written: a rotation on
// SIGHUP, which may come before the line, is the key it names, never the
// key at start.
func TestTheReadinessLineNamesTheKeyInForceAfterALiveRotation(t *testing.T) {
	standInKeyService(t)
	g, _, _ := ksService(t, nil)
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
	seedID := keyIDFor(ed25519.NewKeyFromSeed(testSeed).Public().(ed25519.PublicKey))
	if line := g.readinessLine(addr); line != "gateway on http://127.0.0.1:8080 (authority gateway:test, key "+seedID+")\n" {
		t.Fatalf("the readiness line at start: %q", line)
	}
	g.rereadConfig = func() (engineConfig, error) {
		return engineConfig{signingKeyVersion: ksVersion1, signingPublicKey: hex.EncodeToString(ksKey("one").Public().(ed25519.PublicKey))}, nil
	}
	if _, err := g.rotateOnHangup(ksStamper); err != nil {
		t.Fatalf("the rotation to the key service: %v", err)
	}
	oneID := keyIDFor(ksKey("one").Public().(ed25519.PublicKey))
	if line := g.readinessLine(addr); line != "gateway on http://127.0.0.1:8080 (authority gateway:test, key "+oneID+")\n" {
		t.Fatalf("the readiness line after a rotation: %q", line)
	}
}
