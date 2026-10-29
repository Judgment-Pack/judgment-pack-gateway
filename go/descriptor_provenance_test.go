package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
		if got := checkDescriptorProvenance(root, p, restarted.authority, "tickets/live", "", false, []reachedKey{{key: restarted.publicKey, keyID: restarted.keyID}}); got != "ok" {
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
			if got := checkDescriptorProvenance(s.root, p, s.authority, "tickets/live", "", false, []reachedKey{{key: s.publicKey, keyID: s.keyID}}); got != "descriptor-provenance-mismatch" {
				t.Fatal(got)
			}
		})
	}
}

// Capturing provenance may upgrade an older file but cannot disable newer
// engine requirements or discard a newer configuration member.
func TestDescriptorStatementsPreserveNewerEngineVersion(t *testing.T) {
	for _, version := range []string{"11", "12", "13", "14"} {
		raw := []byte(`{"engineVersion":"` + version + `","sandbox":{"policy":"/policy"},"platforms":{"tickets":{"binding":"tickets@sha256:` + strings.Repeat("a", 64) + `"}}}`)
		rendered, err := renderDescriptorStatements(raw, "tickets", map[string]string{"live": "sha256:" + strings.Repeat("b", 64)})
		if err != nil {
			t.Fatal(err)
		}
		v, err := parseJSON(rendered)
		if err != nil {
			t.Fatal(err)
		}
		o := v.(*vObject)
		want := version
		if version == "11" {
			want = "12"
		}
		got, _ := memberString(o, "engineVersion")
		if got != want {
			t.Fatalf("version %s became %s", version, got)
		}
		sandbox, _ := o.get("sandbox")
		if string(canon(sandbox)) != `{"policy":"/policy"}` {
			t.Fatal("sandbox changed during descriptor capture")
		}
	}
}

// #349 F1: the V2 (taxonomy) capture path renders the platform entry with its
// per-operation approvals first; its own version guard must keep a newer
// engine version and the sandbox member, alone and followed by the statements.
func TestOperationApprovalsPreserveNewerEngineVersion(t *testing.T) {
	for _, version := range []string{"12", "13", "14"} {
		raw := []byte(`{"engineVersion":"` + version + `","sandbox":{"policy":"/policy"},"platforms":{"tickets":{"binding":"tickets@sha256:` + strings.Repeat("a", 64) + `"}}}`)
		req := connectRequest{platform: "tickets", credentials: map[string]string{"live": "/credentials/tickets"}, user: "engine-tickets"}
		pins := map[string]string{"live": "sha256:" + strings.Repeat("b", 64)}
		alone, err := renderOperationPlatformEntry(raw, req, "tickets@sha256:"+strings.Repeat("a", 64), pins, nil)
		if err != nil {
			t.Fatal(err)
		}
		followed, err := renderDescriptorStatements(alone, "tickets", map[string]string{"live": "sha256:" + strings.Repeat("c", 64)})
		if err != nil {
			t.Fatal(err)
		}
		for name, rendered := range map[string][]byte{"alone": alone, "followed by statements": followed} {
			v, err := parseJSON(rendered)
			if err != nil {
				t.Fatal(err)
			}
			o := v.(*vObject)
			if got, _ := memberString(o, "engineVersion"); got != version {
				t.Fatalf("%s: version %s became %s", name, version, got)
			}
			sandbox, _ := o.get("sandbox")
			if string(canon(sandbox)) != `{"policy":"/policy"}` {
				t.Fatalf("%s: sandbox changed during operation capture", name)
			}
		}
	}
}

// #349 F3: an empty statement endpoint records a local capture and covers no
// remote acquisition. The rows are shared with verify-ts.
func TestDescriptorStatementEndpointFollowsTheAcquisitionsTransport(t *testing.T) {
	raw, err := os.ReadFile("../testdata/descriptor-provenance/endpoint-cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		Name              string
		StatementEndpoint string
		Acquisition       map[string]json.RawMessage
		Status            string
	}
	if err = json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		t.Run(row.Name, func(t *testing.T) {
			s, err := newStore(t.TempDir(), testSeed, "gateway:test")
			if err != nil {
				t.Fatal(err)
			}
			p, err := s.retainDescriptorCapture([]byte(goodSnapshot), "live")
			if err != nil {
				t.Fatal(err)
			}
			statement, err := s.artifacts.getBlob(p.statement)
			if err != nil {
				t.Fatal(err)
			}
			v, _ := parseJSON(statement)
			core := newObject()
			for _, name := range v.(*vObject).names {
				if name != "signature" {
					value, _ := v.(*vObject).get(name)
					core.set(name, value)
				}
			}
			core.set("endpoint", vString(row.StatementEndpoint))
			sig := ed25519.Sign(s.private, append([]byte(descriptorStatementContext), canon(core)...))
			core.set("signature", vString(hex.EncodeToString(sig)))
			if p.statement, err = s.retain(canon(core)); err != nil {
				t.Fatal(err)
			}
			receipt, _ := parseJSON(descriptorReceipt(t, s, p))
			o := receipt.(*vObject)
			a := sub(o, "acquisition")
			for name, member := range row.Acquisition {
				value, err := parseJSON(member)
				if err != nil {
					t.Fatal(err)
				}
				a.set(name, value)
			}
			unsigned := newObject()
			for _, name := range o.names {
				if name != "signature" {
					value, _ := o.get(name)
					unsigned.set(name, value)
				}
			}
			signature := ed25519.Sign(s.private, append([]byte(receiptContext3), canon(unsigned)...))
			unsigned.set("signature", vString(hex.EncodeToString(signature)))
			if _, got := checkReceipt(canon(unsigned), s.root, "s1", "1.json", s.authority, s.publicKey, s.keyID); got != row.Status {
				t.Fatalf("status %s, want %s", got, row.Status)
			}
		})
	}
}

// #349 F2: the registry is walked once for descriptor provenance, not on each
// acquisition, and the check after the source runs is made outside the
// gateway-wide lock.
func TestDescriptorProvenanceWalksTheRegistryOnceOutsideTheLock(t *testing.T) {
	g, _ := testService(t)
	p, err := g.store.retainDescriptorCapture([]byte(goodSnapshot), "live")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(envSourceEnvelope, `{"result":{"n":1},"acquisition":{"adapter":{"name":"fixture","version":"1","digest":"sha256:`+strings.Repeat("a", 64)+`"},"endpoint":null,"statement":null,"snapshot":null,"peerIdentity":null,"schema":null,"upstreamToken":null,"observedAt":"2026-10-29T00:00:00Z"}}`)
	g.sources["tickets/live"] = sourceSpec{argv: []string{os.Args[0]}, env: helperEnv, shape: "mcp", descriptorProvenance: &p}
	walks := 0
	g.keyWalk = func() ([]reachedKey, error) { walks++; return g.reachedKeys() }
	rechecks := 0
	g.beforeProvenanceRecheck = func() {
		rechecks++
		if !g.mu.TryLock() {
			t.Error("the provenance check after the run holds the gateway-wide lock")
			return
		}
		g.mu.Unlock()
	}
	for i := range 3 {
		out, err := g.acquire(fmt.Sprintf("provenance-%d", i), "tickets/live", newObject(), nil)
		if err != nil {
			t.Fatal(err)
		}
		acquisition := out["receipt"].(map[string]any)["acquisition"].(map[string]any)
		if acquisition["descriptorProvenance"] == nil {
			t.Fatal("the receipt carries no provenance")
		}
	}
	if walks != 1 || rechecks != 3 {
		t.Fatalf("registry walks %d (want 1), rechecks %d (want 3)", walks, rechecks)
	}
}
