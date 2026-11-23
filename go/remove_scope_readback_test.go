package main

import (
	"net/http"
	"strings"
	"testing"
)

// An uncertain scoped key is settled for remove-scope by a read-back that
// resolves it as /verify resolves one, and by nothing less: a read-back
// that names the action under another key, or that does not verify, leaves
// the key pending.
func TestRemoveScopeReadBackMustResolveTheAction(t *testing.T) {
	h := actScopeSetup(t)
	actionKeysMode(t, h.root, "write", "drop")
	key := strings.Repeat("f", 64)
	if code, out := authed(t, h.server, "/act", h.body("act-r", "tickets-b", scopeB, key, h.decisionB, h.cite("b-read", h.scopedSig)), h.tokenB); code != http.StatusOK {
		t.Fatalf("the uncertain scoped action: %d %v", code, out)
	}
	keys, err := h.g.reachedKeys()
	if err != nil {
		t.Fatal(err)
	}
	read := func() ([]*storedReceipt, *storedReceipt) {
		all, err := readStoreReceipts(h.g.storeRoot, h.g.authority, keys, &retention{})
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range all {
			if s.r != nil && s.r.reconciliation != nil {
				return all, s
			}
		}
		t.Fatal("no read-back in the store")
		return nil, nil
	}
	all, _ := read()
	if refused, err := pendingScopedKeys(h.g.storeRoot, callerScopeB, all); err != nil || len(refused) != 0 {
		t.Fatalf("the resolved key is pending: %v %v", refused, err)
	}
	for name, spoil := range map[string]func(*storedReceipt){
		"of another key":       func(s *storedReceipt) { s.r.reconciliation.key = strings.Repeat("0", 64) },
		"that does not verify": func(s *storedReceipt) { s.status = "signature-mismatch" },
	} {
		all, back := read()
		spoil(back)
		if refused, _ := pendingScopedKeys(h.g.storeRoot, callerScopeB, all); len(refused) != 1 || !strings.Contains(refused[0], key) {
			t.Errorf("a read-back %s settled the key: %v", name, refused)
		}
	}
}
