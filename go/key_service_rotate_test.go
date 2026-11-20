package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// linkOfUnder is the findings --previous gives of the registry at registry
// against the one at previous, both walked from pub.
func linkOfUnder(t *testing.T, registry, previous string, pub ed25519.PublicKey) []finding {
	t.Helper()
	walk := walkRegistry([]byte(readFile(t, registry)), pub)
	rep := &report{OK: true, continuation: walk.continuation, continuationRefused: walk.continuationFinding != nil}
	if err := linkPrevious(rep, previous, pub); err != nil {
		t.Fatal(err)
	}
	return rep.Findings
}

// On the filesystem kind under a key service, gateway store rotate given
// --config seals what is open and signs the continuation under the key
// version the configuration names (ADR-0050): the seed alone is refused
// before anything is written, and with the configuration the old store's
// last seal and the new registry's continuation are under the service's
// key, the new registry links to the old one, and the old store verifies.
func TestStoreRotateSignsThroughTheKeyService(t *testing.T) {
	standIn := standInKeyService(t)
	one := mustKeyServiceSigner(t, ksVersion1)
	serviceKey := keyIDFor(one.publicKey())
	t.Setenv(envSourceHelper, "1")
	root := t.TempDir()
	store, registry := filepath.Join(root, "store"), filepath.Join(root, "registry.jsonl")
	g, err := newGatewayServiceSigned(store, testSeed, one, "gateway:test", registry,
		map[string]sourceSpec{"a": {argv: []string{os.Args[0]}, env: helperEnv, scope: testScope}})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(g.handler())
	if code, out := post(t, server, "/acquire", `{"session":"ks-left","source":"a","scope":`+jsonText(t, testScope)+`,"arguments":{"q":"x"}}`); code != http.StatusOK {
		t.Fatalf("acquire: %d %v", code, out)
	}
	server.Close()
	seedPath := writeSeedFile(t, t.TempDir(), testSeed)
	dir := t.TempDir()
	newStore, newRegistry := filepath.Join(dir, "store"), filepath.Join(dir, "registry.jsonl")
	before := readFile(t, registry)

	var stdout, stderr bytes.Buffer
	code := cmdStoreRotateAt([]string{"--store", store, "--seed", seedPath, "--registry", registry, "--authority", "gateway:test",
		"--new-store", newStore, "--new-registry", newRegistry}, &stdout, &stderr, fixedStamp("2026-11-19T00:00:01Z"))
	if code != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "no rotation in the registry leads from it") {
		t.Fatalf("the seed over a key service's store: %d %q %q", code, stdout.String(), stderr.String())
	}
	if readFile(t, registry) != before {
		t.Fatal("the seed's refusal changed the registry")
	}
	if _, err := os.Lstat(newRegistry); !os.IsNotExist(err) {
		t.Fatalf("the seed's refusal made the new registry: %v", err)
	}

	config := filepath.Join(t.TempDir(), "engine.json")
	body := fmt.Sprintf(`{"engineVersion":%q,"authority":"gateway:test","seed":%q,"store":%q,"registry":%q,"decisionRecords":%q,"listen":"127.0.0.1:8787","catalog":%q,"signingKeyVersion":%q,"signingPublicKey":%q,"platforms":{}}`,
		keyServiceSignerVersion, seedPath, store, registry, filepath.Join(root, "decisions"), filepath.Join(root, "catalog"), ksVersion1, hex.EncodeToString(one.publicKey()))
	if err := os.WriteFile(config, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	asked := standIn.requests
	stdout.Reset()
	stderr.Reset()
	code = cmdStoreRotateAt([]string{"--config", config, "--new-store", newStore, "--new-registry", newRegistry}, &stdout, &stderr, fixedStamp("2026-11-19T00:00:02Z"))
	if code != 0 || strings.TrimPrefix(stderr.String(), sealOpenUnlocked()) != "" || standIn.requests <= asked {
		t.Fatalf("store rotate through the key service: %d %q %q, %d requests after %d", code, stdout.String(), stderr.String(), standIn.requests, asked)
	}
	out := strings.Split(strings.TrimSuffix(stdout.String(), "\n"), "\n")
	if len(out) != 2 || !strings.Contains(out[0], `"sessionId":"ks-left"`) || !strings.Contains(out[0], `"keyId":"`+serviceKey+`"`) {
		t.Fatalf("the seal of the session left open is not under the service's key: %q", stdout.String())
	}
	if !strings.HasSuffix(readFile(t, registry), out[0]+"\n") {
		t.Fatal("the old registry does not end in the seal printed")
	}
	if got := readFile(t, newRegistry); got != out[1]+"\n" || !strings.Contains(got, `"keyId":"`+serviceKey+`"`) {
		t.Fatalf("the continuation is not under the service's key: %q", got)
	}
	if f := linkOfUnder(t, newRegistry, registry, one.publicKey()); len(f) != 0 {
		t.Fatalf("the link to the old registry: %v", f)
	}
	if rep, err := verifyWithRegistry(store, registry, "gateway:test", one.publicKey()); err != nil || !rep.OK {
		t.Fatalf("the old store after the rotation: %v %+v", err, rep)
	}
	if strings.Contains(readFile(t, registry)+readFile(t, newRegistry), `"keyId":"`+keyIDFor(ed25519.NewKeyFromSeed(testSeed).Public().(ed25519.PublicKey))+`"`) {
		t.Fatal("something was signed under the seed's key")
	}
}
