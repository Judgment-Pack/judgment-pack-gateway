package main

// The key-service signer (ADR-0050) against in-process stand-ins for the
// metadata server and the key service: no real endpoint, no credential.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io/fs"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const (
	ksVersion1 = "projects/standin-project/locations/global/keyRings/receipts/cryptoKeys/gateway/cryptoKeyVersions/1"
	ksVersion2 = "projects/standin-project/locations/global/keyRings/receipts/cryptoKeys/gateway/cryptoKeyVersions/2"
	ksToken    = "standin-access-token"
)

func ksKey(word string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("key-service-standin/" + word))
	return ed25519.NewKeyFromSeed(seed[:])
}

// keyServiceStandIn answers publicKey and asymmetricSign for the versions
// it holds, as the key service does, and the access token as the metadata
// server does. Its faults are set by a test between calls.
type keyServiceStandIn struct {
	mu       sync.Mutex
	keys     map[string]ed25519.PrivateKey
	requests int
	// signStatus, where not 0, answers every sign with it; signBy, where
	// not nil, signs with it in place of the version's key; publicKey,
	// where not nil, rewrites the publicKey answer; redirect, where not "",
	// answers every sign with a redirect to it; tokenStatus, where not 0,
	// answers the token request with it.
	signStatus  int
	signBy      ed25519.PrivateKey
	publicKey   func(map[string]string)
	redirect    string
	tokenStatus int
	// signName, where not "", is the version a sign answer names;
	// tokenBody, where not "", is the metadata server's whole answer
	signName  string
	tokenBody string
	kms       *httptest.Server
	metadata  *httptest.Server
}

func standInKeyService(t *testing.T) *keyServiceStandIn {
	t.Helper()
	s := &keyServiceStandIn{keys: map[string]ed25519.PrivateKey{ksVersion1: ksKey("one"), ksVersion2: ksKey("two")}}
	s.kms = httptest.NewTLSServer(http.HandlerFunc(s.serveKMS))
	s.metadata = httptest.NewServer(http.HandlerFunc(s.serveMetadata))
	t.Cleanup(s.kms.Close)
	t.Cleanup(s.metadata.Close)
	roots := x509.NewCertPool()
	roots.AddCert(s.kms.Certificate())
	base, metadata, before := keyServiceBase, keyServiceMetadataBase, keyServiceRoots
	keyServiceBase, keyServiceMetadataBase, keyServiceRoots = s.kms.URL, s.metadata.URL, roots
	t.Cleanup(func() { keyServiceBase, keyServiceMetadataBase, keyServiceRoots = base, metadata, before })
	return s
}

func (s *keyServiceStandIn) set(f func(*keyServiceStandIn)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f(s)
}

func (s *keyServiceStandIn) serveMetadata(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	status, body := s.tokenStatus, s.tokenBody
	s.mu.Unlock()
	if r.Header.Get("Metadata-Flavor") != "Google" || r.URL.Path != metadataAccessPath {
		http.Error(w, "no", http.StatusForbidden)
		return
	}
	w.Header().Set("Metadata-Flavor", "Google")
	if status != 0 {
		w.WriteHeader(status)
		return
	}
	if body != "" {
		w.Write([]byte(body))
		return
	}
	w.Write([]byte(`{"access_token":"` + ksToken + `","expires_in":3599,"token_type":"Bearer"}`))
}

func (s *keyServiceStandIn) serveKMS(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests++
	if r.Header.Get("Authorization") != "Bearer "+ksToken {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/v1/")
	if version, ok := strings.CutSuffix(path, "/publicKey"); ok && r.Method == http.MethodGet {
		key, held := s.keys[version]
		if !held {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		der, _ := x509.MarshalPKIXPublicKey(key.Public())
		pemText := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
		answer := map[string]string{"name": version, "pem": pemText, "algorithm": keyServiceAlgorithm, "pemCrc32c": crc32c([]byte(pemText)), "protectionLevel": "SOFTWARE"}
		if s.publicKey != nil {
			s.publicKey(answer)
		}
		json.NewEncoder(w).Encode(answer)
		return
	}
	version, ok := strings.CutSuffix(path, ":asymmetricSign")
	key, held := s.keys[version]
	if !ok || !held || r.Method != http.MethodPost {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if s.redirect != "" {
		http.Redirect(w, r, s.redirect, http.StatusFound)
		return
	}
	if s.signStatus != 0 {
		w.WriteHeader(s.signStatus)
		return
	}
	var asked struct{ Data, DataCrc32c string }
	if err := json.NewDecoder(r.Body).Decode(&asked); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	data, err := base64.StdEncoding.DecodeString(asked.Data)
	if err != nil || asked.DataCrc32c != crc32c(data) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if s.signBy != nil {
		key = s.signBy
	}
	signature := ed25519.Sign(key, data)
	if s.signName != "" {
		version = s.signName
	}
	json.NewEncoder(w).Encode(map[string]any{"name": version, "signature": base64.StdEncoding.EncodeToString(signature),
		"signatureCrc32c": crc32c(signature), "verifiedDataCrc32c": true, "protectionLevel": "SOFTWARE"})
}

func mustKeyServiceSigner(t *testing.T, version string) *keyServiceSigner {
	t.Helper()
	k, _, err := newKeyServiceSigner(version)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// storeFiles is every file under root, by its path and bytes.
func storeFiles(t *testing.T, root string) map[string]string {
	t.Helper()
	files := map[string]string{}
	filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			data, _ := os.ReadFile(path)
			files[path] = string(data)
		} else if err == nil && d.IsDir() && path != root {
			files[path+"/"] = ""
		}
		return nil
	})
	return files
}

func ksService(t *testing.T, sig signer) (g *gatewayService, store, registry string) {
	t.Helper()
	t.Setenv(envSourceHelper, "1")
	root := t.TempDir()
	store, registry = filepath.Join(root, "store"), filepath.Join(root, "registry.jsonl")
	sources := map[string]sourceSpec{"screening": {argv: []string{os.Args[0]}, env: helperEnv}}
	g, err := newGatewayServiceSigned(store, testSeed, sig, "gateway:test", registry, sources)
	if err != nil {
		t.Fatal(err)
	}
	return g, store, registry
}

// The seed's signer signs the bytes the seed always signed: a receipt's
// signature is ed25519.Sign over its context and canonical core, and a
// rotation's record signed through two seeds' keys is rotationRecord's.
func TestTheSeedSignerSignsTheBytesTheSeedAlwaysSigned(t *testing.T) {
	st, err := newStore(t.TempDir(), testSeed, "gateway:test")
	if err != nil {
		t.Fatal(err)
	}
	core := newObject()
	core.set("callIndex", vInt(0))
	core.set("sessionId", vString("seeded"))
	core.set("source", vString("screening"))
	_, signature, err := st.stamp(core)
	if err != nil {
		t.Fatal(err)
	}
	private := ed25519.NewKeyFromSeed(testSeed)
	if want := hex.EncodeToString(ed25519.Sign(private, append([]byte(receiptContext), canon(core)...))); signature != want || st.keyID != keyIDFor(private.Public().(ed25519.PublicKey)) {
		t.Fatalf("the seed's receipt signature changed: %s, want %s", signature, want)
	}
	from, to := ksKey("from"), ksKey("to")
	signed, err := rotationRecordSigned([]byte("x"), 1, "2026-11-19T00:00:00Z", newSigningKey(seedSigner{from}), newSigningKey(seedSigner{to}))
	if err != nil || !bytes.Equal(signed, rotationRecord([]byte("x"), 1, "2026-11-19T00:00:00Z", from, to)) {
		t.Fatalf("a rotation signed through the seed signer is not rotationRecord's bytes: %v", err)
	}
}

// A gateway the key service signs for mints receipts and seals the
// existing verifier accepts, pinned at the service's key, and none under
// the seed's key.
func TestTheKeyServiceSignsReceiptsTheVerifierAccepts(t *testing.T) {
	standIn := standInKeyService(t)
	k, line, err := newKeyServiceSigner(ksVersion1)
	if err != nil || !strings.Contains(line, "protection level SOFTWARE") || !bytes.Equal(k.publicKey(), ksKey("one").Public().(ed25519.PublicKey)) {
		t.Fatalf("the start: %v %q", err, line)
	}
	g, store, registry := ksService(t, k)
	mustAcquire(t, g, "served")
	mustAcquire(t, g, "served")
	mustSeal(t, g, "served")
	if rep, err := verifyWithRegistry(store, registry, "gateway:test", k.publicKey()); err != nil || !rep.OK {
		t.Fatalf("the verifier refused the key service's receipts: %v %+v", err, rep)
	}
	if rep, err := verifyWithRegistry(store, registry, "gateway:test", ed25519.NewKeyFromSeed(testSeed).Public().(ed25519.PublicKey)); err == nil && rep.OK {
		t.Fatal("the store verifies under the seed's key, which signed nothing")
	}
	if standIn.requests < 4 { // the public key, two receipts, a seal
		t.Fatalf("the key service was asked %d times", standIn.requests)
	}
}

// A key service that refuses, throttles, cannot be reached, redirects, or
// answers a signature that does not verify under the gateway's key fails
// the acquisition, and the seal, closed, with the fixed sentence: nothing
// is minted, and the store and the registry are as they were.
func TestAKeyServiceThatDoesNotSignFailsClosedWithNothingStored(t *testing.T) {
	elsewhere := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("a redirect away from the key service was followed: %s", r.URL)
	}))
	defer elsewhere.Close()
	for _, tc := range []struct {
		name  string
		fault func(*keyServiceStandIn)
		want  error
	}{
		{"wrong signature", func(s *keyServiceStandIn) { s.signBy = ksKey("another") }, errSignatureNotVerified},
		{"refused", func(s *keyServiceStandIn) { s.signStatus = http.StatusForbidden }, errKeyServiceRefused},
		{"429", func(s *keyServiceStandIn) { s.signStatus = http.StatusTooManyRequests }, errKeyServiceRefused},
		{"503", func(s *keyServiceStandIn) { s.signStatus = http.StatusServiceUnavailable }, errKeyServiceRefused},
		{"redirect", func(s *keyServiceStandIn) { s.redirect = elsewhere.URL + "/v1/x" }, errKeyServiceRefused},
		{"token refused", func(s *keyServiceStandIn) { s.tokenStatus = http.StatusInternalServerError }, errKeyServiceToken},
		{"unreachable", func(s *keyServiceStandIn) { s.kms.CloseClientConnections(); s.kms.Listener.Close() }, errKeyServiceUnreachable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			standIn := standInKeyService(t)
			k := mustKeyServiceSigner(t, ksVersion1)
			// sealed holds a session to seal; served mints its first receipt
			// under the fault, so its payload is in no store yet
			sealed, _, registry := ksService(t, k)
			mustAcquire(t, sealed, "first")
			served, store, _ := ksService(t, k)
			if tc.name == "token refused" {
				k.mu.Lock()
				k.token = ""
				k.mu.Unlock()
			}
			before, registryBefore := storeFiles(t, store), storeFiles(t, filepath.Dir(registry))
			standIn.set(tc.fault)
			_, err := served.acquire("second", "screening", vString("second"), nil)
			if !errors.Is(err, tc.want) || err.Error() != tc.want.Error() {
				t.Fatalf("the acquisition: %v, want %q", err, tc.want)
			}
			if _, err := sealed.sealSession("first"); err == nil || err.Error() != tc.want.Error() {
				t.Fatalf("the seal: %v, want %q", err, tc.want)
			}
			if after := storeFiles(t, store); !maps.Equal(after, before) {
				t.Fatalf("the store changed: %d entries before, %d after", len(before), len(after))
			}
			if after := storeFiles(t, filepath.Dir(registry)); after[registry] != registryBefore[registry] {
				t.Fatal("the registry changed")
			}
		})
	}
}

// The public key is read once, at start, and held: the version asked,
// EC_SIGN_ED25519, its CRC32C, one Ed25519 key; a key version out of form
// is refused before the service is asked.
func TestTheKeyServicesPublicKeyIsCheckedAtStart(t *testing.T) {
	standIn := standInKeyService(t)
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&p256.PublicKey)
	otherPem := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	for name, rewrite := range map[string]func(map[string]string){
		"algorithm": func(a map[string]string) { a["algorithm"] = "EC_SIGN_P256_SHA256" },
		"name":      func(a map[string]string) { a["name"] = ksVersion2 },
		"crc32c":    func(a map[string]string) { a["pemCrc32c"] = "1" },
		"not ed25519": func(a map[string]string) {
			a["pem"], a["pemCrc32c"] = otherPem, crc32c([]byte(otherPem))
		},
	} {
		standIn.set(func(s *keyServiceStandIn) { s.publicKey = rewrite })
		if _, _, err := newKeyServiceSigner(ksVersion1); !errors.Is(err, errKeyServicePublicKey) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	standIn.set(func(s *keyServiceStandIn) { s.publicKey = nil; s.requests = 0 })
	for _, bad := range []string{"projects/standin-project/locations/global/keyRings/r/cryptoKeys/k", ksVersion1 + "/../2", "https://elsewhere/" + ksVersion1, strings.Replace(ksVersion1, "Versions/1", "Versions/0", 1)} {
		if _, _, err := newKeyServiceSigner(bad); err == nil || !strings.Contains(err.Error(), "not of the form") {
			t.Fatalf("%q: %v", bad, err)
		}
	}
	if standIn.requests != 0 {
		t.Fatal("the key service was asked for a key version out of form")
	}
	// a key version the registry rotated from is refused by the registry's
	// walk at start (TestARotationWhileServingKeepsEachReceiptUnderOneKeyVersion)
}

// A rotation while serving: a receipt begun under the first key version is
// signed by it and names it, though the rotation is recorded while it is
// minted; every receipt after the switch is under the next; the store, old
// receipts with it, verifies from the registry alone, pinned at the first
// key; the next seals are the next key's; and the gateway starts again
// under the next key alone.
func TestARotationWhileServingKeepsEachReceiptUnderOneKeyVersion(t *testing.T) {
	standInKeyService(t)
	one, two := mustKeyServiceSigner(t, ksVersion1), mustKeyServiceSigner(t, ksVersion2)
	g, store, registry := ksService(t, one)
	mustAcquire(t, g, "before")
	mustSeal(t, g, "before")
	var once sync.Once
	afterReceiptKeyChosen = func() {
		once.Do(func() {
			if _, err := g.registry.rotateTo(two, "2026-11-19T00:00:00Z"); err != nil {
				t.Errorf("the rotation: %v", err)
			}
		})
	}
	defer func() { afterReceiptKeyChosen = nil }()
	mustAcquire(t, g, "during")
	afterReceiptKeyChosen = nil
	mustAcquire(t, g, "during")
	mustAcquire(t, g, "after")
	mustSeal(t, g, "during")
	mustSeal(t, g, "after")
	for at, want := range map[string]ed25519.PublicKey{"during/0.json": one.publicKey(), "during/1.json": two.publicKey(), "after/0.json": two.publicKey()} {
		data, err := os.ReadFile(filepath.Join(store, "receipts", at))
		if err != nil || !bytes.Contains(data, []byte(`"keyId":"`+keyIDFor(want)+`"`)) {
			t.Fatalf("%s is not under the key it was begun under: %v %s", at, err, data)
		}
	}
	rep, err := verifyWithRegistry(store, registry, "gateway:test", one.publicKey())
	if err != nil || !rep.OK || rep.Rotations.Count != 1 {
		t.Fatalf("the store after a rotation while serving: %v %+v", err, rep)
	}
	data, _ := os.ReadFile(registry)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if !strings.Contains(lines[len(lines)-1], keyIDFor(two.publicKey())) {
		t.Fatal("the seal after the rotation is not the next key's")
	}
	sources := map[string]sourceSpec{"screening": {argv: []string{os.Args[0]}, env: helperEnv}}
	if _, err := newGatewayServiceSigned(store, testSeed, one, "gateway:test", registry, sources); err == nil {
		t.Fatal("the gateway started again under the key version it rotated from")
	}
	if _, err := newGatewayServiceSigned(store, testSeed, two, "gateway:test", registry, sources); err != nil {
		t.Fatalf("the gateway did not start under the next key version: %v", err)
	}
	if _, err := g.registry.rotateTo(two, "2026-11-19T00:00:01Z"); err == nil {
		t.Fatal("a rotation to the key the gateway holds")
	}
}

// signingKeyVersion is a version-36 member, of its closed form; version 35
// is reserved and read by no engine.
func TestSigningKeyVersionIsAVersion36MemberOfItsForm(t *testing.T) {
	catalog := catalogWith(t, map[string]string{"records": tokenBinding})
	ref := "records@" + digestOf(tokenBinding)
	adapters := `,"adapters":"` + abs(t, t.TempDir(), "bin") + `"`
	platform := tokenPlatformJSON(t, "records", ref, "engine-docs", ``, ``)
	member := func(v string) string { return adapters + `,"signingKeyVersion":"` + v + `"` }
	cfg, _, err := load(t, atVersion(t, keyServiceSignerVersion, catalog, member(ksVersion1), platform))
	if err != nil || cfg.signingKeyVersion != ksVersion1 {
		t.Fatalf("version 36: %v %q", err, cfg.signingKeyVersion)
	}
	if cfg, _, err := load(t, atVersion(t, keyServiceSignerVersion, catalog, adapters, platform)); err != nil || cfg.signingKeyVersion != "" {
		t.Fatalf("version 36 without the member: %v", err)
	}
	if _, _, err := load(t, atVersion(t, assertionAlgorithmVersion, catalog, member(ksVersion1), platform)); err == nil || !strings.Contains(err.Error(), "version-36 member") {
		t.Fatalf("version 34: %v", err)
	}
	if _, _, err := load(t, atVersion(t, "35", catalog, member(ksVersion1), platform)); err == nil || !strings.Contains(err.Error(), "unsupported engineVersion") {
		t.Fatalf("version 35: %v", err)
	}
	for _, bad := range []string{"", ksVersion1 + "x/", "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1", "https://cloudkms.googleapis.com/v1/" + ksVersion1} {
		if _, _, err := load(t, atVersion(t, keyServiceSignerVersion, catalog, member(bad), platform)); err == nil || !strings.Contains(err.Error(), "resource name") {
			t.Fatalf("%q: %v", bad, err)
		}
	}
}
