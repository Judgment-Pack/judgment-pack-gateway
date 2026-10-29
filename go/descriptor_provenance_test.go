package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func connectedTestService(t *testing.T, cfg engineConfig) (*gatewayService, *httptest.Server) {
	t.Helper()
	seed, err := loadSeed(cfg.seed)
	if err != nil {
		t.Fatal(err)
	}
	g, err := newGatewayService(cfg.store, seed, cfg.authority, cfg.registry, map[string]sourceSpec{})
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewServer(g.handler())
	t.Cleanup(s.Close)
	return g, s
}

func descriptorReceipt(t *testing.T, s *store, p descriptorProvenance) []byte {
	t.Helper()
	o, _ := receipt3("acquisition", nil)
	core := newObject()
	for _, name := range o.names {
		if name != "signature" {
			v, _ := o.get(name)
			core.set(name, v)
		}
	}
	result, err := s.retain([]byte(`{"n":0}`))
	if err != nil {
		t.Fatal(err)
	}
	core.set("resultDigest", vString(result))
	core.set("source", vString("tickets/live"))
	core.set("authority", vString(s.authority))
	core.set("keyId", vString(s.keyID))
	a := sub(core, "acquisition")
	a.set("shape", vString("mcp"))
	a.set("descriptorProvenance", p.value())
	signature := ed25519.Sign(s.private, append([]byte(receiptContext3), canon(core)...))
	core.set("signature", vString(hex.EncodeToString(signature)))
	return canon(core)
}

func TestDescriptorProvenanceReceiptRequiresBothRetainedArtifacts(t *testing.T) {
	for _, remove := range []string{"", "snapshot", "statement", "changed-snapshot", "changed-statement"} {
		t.Run(remove, func(t *testing.T) {
			s, err := newStore(t.TempDir(), testSeed, "gateway:test")
			if err != nil {
				t.Fatal(err)
			}
			p, err := s.retainDescriptorCapture([]byte(goodSnapshot), "live")
			if err != nil {
				t.Fatal(err)
			}
			raw := descriptorReceipt(t, s, p)
			want := "ok"
			if remove != "" {
				pin := p.snapshot
				if strings.Contains(remove, "statement") {
					pin = p.statement
				}
				file := filepath.Join(s.root, "artifacts", strings.TrimPrefix(pin, "sha256:"))
				if strings.HasPrefix(remove, "changed-") {
					err = os.WriteFile(file, []byte(`{}`), 0600)
					want = "descriptor-provenance-mismatch"
				} else {
					err = os.Remove(file)
					want = "descriptor-provenance-missing"
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			_, got := checkReceipt(raw, s.root, "s1", "1.json", s.authority, s.publicKey, s.keyID)
			if got != want {
				t.Fatalf("got %s, want %s", got, want)
			}
		})
	}
}

func TestDescriptorStatementCannotBeSplicedAcrossItsClaims(t *testing.T) {
	for _, change := range []string{"authority", "source", "binding", "snapshot", "endpoint", "capturedAt", "keyId", "statementVersion", "signature", "extra", "domain"} {
		t.Run(change, func(t *testing.T) {
			s, err := newStore(t.TempDir(), testSeed, "gateway:test")
			if err != nil {
				t.Fatal(err)
			}
			p, err := s.retainDescriptorCapture([]byte(goodSnapshot), "live")
			if err != nil {
				t.Fatal(err)
			}
			raw, err := s.artifacts.getBlob(p.statement)
			if err != nil {
				t.Fatal(err)
			}
			v, err := parseJSON(raw)
			if err != nil {
				t.Fatal(err)
			}
			o := v.(*vObject)
			core := newObject()
			for _, name := range o.names {
				if name != "signature" {
					value, _ := o.get(name)
					core.set(name, value)
				}
			}
			var replacement map[string]string
			cases, err := os.ReadFile("../testdata/descriptor-provenance/statement-mutations.json")
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(cases, &replacement); err != nil {
				t.Fatal(err)
			}
			if value, ok := replacement[change]; ok {
				core.set(change, vString(value))
			}
			prefix := descriptorStatementContext
			if change == "domain" {
				prefix = receiptContext3
			}
			sig := ed25519.Sign(s.private, append([]byte(prefix), canon(core)...))
			if change == "signature" {
				sig[0] ^= 1
			}
			core.set("signature", vString(hex.EncodeToString(sig)))
			p.statement, err = s.retain(canon(core))
			if err != nil {
				t.Fatal(err)
			}
			_, got := checkReceipt(descriptorReceipt(t, s, p), s.root, "s1", "1.json", s.authority, s.publicKey, s.keyID)
			if got != "descriptor-provenance-mismatch" {
				t.Fatal("spliced statement accepted:", got)
			}
		})
	}
}

func TestDescriptorCaptureChangesIdentityAndSurvivesRestart(t *testing.T) {
	root := t.TempDir()
	s, err := newStore(root, testSeed, "gateway:test")
	if err != nil {
		t.Fatal(err)
	}
	first, err := s.retainDescriptorCapture([]byte(goodSnapshot), "live")
	if err != nil {
		t.Fatal(err)
	}
	changed := strings.Replace(goodSnapshot, "2026-09-15T01:02:03Z", "2026-09-15T01:02:04Z", 1)
	second, err := s.retainDescriptorCapture([]byte(changed), "live")
	if err != nil {
		t.Fatal(err)
	}
	if first.snapshot == second.snapshot || first.statement == second.statement {
		t.Fatal("recapture reused old identity")
	}
	restarted, err := newStore(root, testSeed, "gateway:test")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []descriptorProvenance{first, second} {
		if got := checkDescriptorProvenance(root, p, restarted.authority, "tickets/live", "", []reachedKey{{key: restarted.publicKey, keyID: restarted.keyID}}); got != "ok" {
			t.Fatal(got)
		}
	}
}

func TestDescriptorMissingRefusesBeforeSourceExecution(t *testing.T) {
	g, _ := testService(t)
	p, err := g.store.retainDescriptorCapture([]byte(goodSnapshot), "live")
	if err != nil {
		t.Fatal(err)
	}
	g.sources["tickets/live"] = sourceSpec{argv: []string{os.Args[0]}, env: helperEnv, shape: "mcp", descriptorProvenance: &p}
	if err := os.Remove(filepath.Join(g.storeRoot, "artifacts", strings.TrimPrefix(p.statement, "sha256:"))); err != nil {
		t.Fatal(err)
	}
	if _, err := g.acquire("refused", "tickets/live", newObject(), nil); err == nil || !strings.Contains(err.Error(), "descriptor-provenance-missing") {
		t.Fatal(err)
	}
	if g.started.Load() != 0 {
		t.Fatal("source ran without its captured statement")
	}
}

func TestDescriptorStatementCannotUseAFutureRotationKey(t *testing.T) {
	root := t.TempDir()
	old, err := newStore(root, testSeed, "gateway:test")
	if err != nil {
		t.Fatal(err)
	}
	seed := append([]byte(nil), testSeed...)
	seed[0] ^= 1
	next, err := newStore(root, seed, "gateway:test")
	if err != nil {
		t.Fatal(err)
	}
	keys := []reachedKey{{key: old.publicKey, keyID: old.keyID}, {key: next.publicKey, keyID: next.keyID}}
	future, err := next.retainDescriptorCapture([]byte(goodSnapshot), "live")
	if err != nil {
		t.Fatal(err)
	}
	_, status := checkReceiptUnder(descriptorReceipt(t, old, future), root, "s1", "1.json", old.authority, keys)
	if status != "descriptor-provenance-mismatch" {
		t.Fatal("future key accepted", status)
	}
	past, err := old.retainDescriptorCapture([]byte(goodSnapshot), "live")
	if err != nil {
		t.Fatal(err)
	}
	_, status = checkReceiptUnder(descriptorReceipt(t, next, past), root, "s1", "1.json", next.authority, keys)
	if status != "ok" {
		t.Fatal("reached earlier key refused", status)
	}
}

func TestDescriptorStatementRequiresEveryMember(t *testing.T) {
	for _, missing := range []string{"statementVersion", "authority", "keyId", "source", "binding", "snapshot", "endpoint", "capturedAt", "signature"} {
		t.Run(missing, func(t *testing.T) {
			s, err := newStore(t.TempDir(), testSeed, "gateway:test")
			if err != nil {
				t.Fatal(err)
			}
			p, err := s.retainDescriptorCapture([]byte(goodSnapshot), "live")
			if err != nil {
				t.Fatal(err)
			}
			raw, err := s.artifacts.getBlob(p.statement)
			if err != nil {
				t.Fatal(err)
			}
			v, err := parseJSON(raw)
			if err != nil {
				t.Fatal(err)
			}
			o := v.(*vObject)
			core := newObject()
			for _, name := range o.names {
				if name != missing && name != "signature" {
					value, _ := o.get(name)
					core.set(name, value)
				}
			}
			if missing != "signature" {
				sig := ed25519.Sign(s.private, append([]byte(descriptorStatementContext), canon(core)...))
				core.set("signature", vString(hex.EncodeToString(sig)))
			}
			p.statement, err = s.retain(canon(core))
			if err != nil {
				t.Fatal(err)
			}
			if got := checkDescriptorProvenance(s.root, p, s.authority, "tickets/live", "", []reachedKey{{key: s.publicKey, keyID: s.keyID}}); got != "descriptor-provenance-mismatch" {
				t.Fatal(got)
			}
		})
	}
}
