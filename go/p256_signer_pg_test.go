package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// gateway store rotate-key moves the PostgreSQL kind's key from an Ed25519
// key version to a P-256 one, on to another P-256 one, and back to Ed25519,
// naming the move from the HSM key on one stderr line (ADR-0053 §7); the
// walk reaches every key with its algorithm, and an instance started under
// the last serves a key history of both.
func TestAPostgresStoreRotateKeyCrossesAlgorithms(t *testing.T) {
	standInKeyService(t)
	s := newRkStore(t)
	text, err := os.ReadFile(s.versions[ksVersion1])
	if err != nil {
		t.Fatal(err)
	}
	pinned := `"signingKeyVersion":"` + ksVersion1 + `","signingPublicKey":"` + hex.EncodeToString(ksKey("one").Public().(ed25519.PublicKey)) + `"`
	points := map[string]string{}
	for i, version := range []string{ksP256One, ksP256Two} {
		points[version] = hex.EncodeToString(compressedOf(p256Key(byte(i + 1))))
		keyed := bytes.Replace(text, []byte(`{"engineVersion":"36"`), []byte(`{"engineVersion":"40"`), 1)
		keyed = bytes.Replace(keyed, []byte(pinned), []byte(`"signingKeyVersion":"`+version+`","signingPublicKey":"`+points[version]+`","signingKeyAlgorithm":"ES256"`), 1)
		path := filepath.Join(s.dir, fmt.Sprintf("engine-p256-%d.json", i+1))
		if err := os.WriteFile(path, keyed, 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := parseEngineConfig(keyed)
		if err != nil || cfg.signingKeyAlgorithm != algES256 {
			t.Fatalf("the P-256 configuration: %v", err)
		}
		s.versions[version], s.cfgs[version] = path, cfg
	}
	fromP256 := func(version string) []string {
		return []string{"--from-key-version", version, "--from-public-key", points[version], "--from-key-algorithm", "ES256"}
	}

	a := s.start(t, "", nil)
	server := httptest.NewServer(a.service.handler())
	rkCall(t, server, "rk-sealed", "plain", true)
	server.Close()
	a.stop(&s.said)

	if code, _, stderr := s.rotate(t, ksP256One, "--from-key-version", ksVersion1, "--from-public-key", points[ksP256One]); code != 2 || !strings.Contains(stderr, "64 lowercase") {
		t.Fatalf("a point named without --from-key-algorithm: %d %q", code, stderr)
	}
	if code, _, stderr := s.rotate(t, ksP256One, "--from-key-version", ksVersion1, "--from-public-key", points[ksP256One], "--from-key-algorithm", "EdDSA"); code != 2 || !strings.Contains(stderr, "--from-key-algorithm is ES256") {
		t.Fatalf("another algorithm: %d %q", code, stderr)
	}
	steps := []struct {
		to   string
		from []string
		hsm  bool
	}{
		{ksVersion1, nil, false},
		{ksP256One, rkFrom(t, ksVersion1), false},
		{ksP256Two, fromP256(ksP256One), false},
		{ksVersion2, fromP256(ksP256Two), true},
	}
	for i, step := range steps {
		code, stdout, stderr := s.rotate(t, step.to, step.from...)
		if code != 0 || strings.Count(stderr, hsmToSoftwareLine) != map[bool]int{false: 0, true: 1}[step.hsm] {
			t.Fatalf("rotation %d to %s: %d %q %q", i+1, step.to, code, stdout, stderr)
		}
	}
	w := walkRegistry(s.registry(t), ed25519.NewKeyFromSeed(testSeed).Public().(ed25519.PublicKey))
	if w.finding != nil || len(w.keys) != 5 {
		t.Fatalf("the walk: %v %d", w.finding, len(w.keys))
	}
	for i, alg := range []string{algEd25519, algEd25519, algES256, algES256, algEd25519} {
		if w.keys[i].alg != alg {
			t.Fatalf("key %d is reached as %q", i, w.keys[i].alg)
		}
	}

	b := s.start(t, ksVersion2, mustKeyServiceSigner(t, ksVersion2))
	server = httptest.NewServer(b.service.handler())
	resp, err := http.Get(server.URL + keyHistoryRoute)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || strings.Count(string(body), `"alg":"ES256"`) != 2 || strings.Count(string(body), `"publicKey"`) != 5 {
		t.Fatalf("/publickey/history: %d %s", resp.StatusCode, body)
	}
	if got := rkCall(t, server, "rk-after", "plain", true); got != keyIDFor(ksKey("two").Public().(ed25519.PublicKey)) {
		t.Fatalf("the receipt after the move back names %s", got)
	}
	server.Close()
	b.stop(&s.said)
}
