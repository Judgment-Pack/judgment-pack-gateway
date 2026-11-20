package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// gateway export signs nothing, but reads the gateway's key through the
// configuration as every command does (ADR-0050): a store a key service
// signs for, exported under the configuration naming its key version,
// is exported, and the exported store verifies under the service's key.
func TestExportOfAKeyServiceStoreVerifies(t *testing.T) {
	standInKeyService(t)
	one := mustKeyServiceSigner(t, ksVersion1)
	store, registry, seedPath := ksCommandStore(t, one, false)
	root := t.TempDir()
	config := filepath.Join(root, "engine.json")
	body := fmt.Sprintf(`{"engineVersion":%q,"authority":"gateway:test","seed":%q,"store":%q,"registry":%q,"decisionRecords":%q,"listen":"127.0.0.1:8787","catalog":%q,"platforms":{},"signingKeyVersion":%q,"signingPublicKey":%q}`,
		keyServiceSignerVersion, seedPath, store, registry, filepath.Join(root, "decisions"), filepath.Join(root, "catalog"), ksVersion1, hex.EncodeToString(one.publicKey()))
	if err := os.WriteFile(config, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(root, "exported")
	if _, err := exportEngine(config, out, nil, ""); err != nil {
		t.Fatalf("export of a key service's store: %v", err)
	}
	rep, err := verifyWithRegistry(filepath.Join(out, "store"), filepath.Join(out, "registry"), "gateway:test", one.publicKey())
	if err != nil || !rep.OK {
		t.Fatalf("the exported store: %v %+v", err, rep)
	}
	exported, err := os.ReadFile(filepath.Join(out, "registry"))
	if err != nil || !strings.Contains(string(exported), `"sessionId":"sealed"`) {
		t.Fatalf("the exported registry does not hold the sealed session: %v %s", err, exported)
	}
}
