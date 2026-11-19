package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"adapters/httpsource"
)

// --assertion-alg reaches the token step: an unknown value, or one beside a
// federated token, is refused (status 1) before any key is read, and PS256 beside a P-256 key is no
// credential (status 3) in the sentence that names PS256; none sends a
// token request.
func TestRunTakesTheAssertionAlgorithm(t *testing.T) {
	tokenHits := 0
	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenHits++
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer tokenEndpoint.Close()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	creds := filepath.Join(dir, "credentials.json")
	data, _ := json.Marshal(map[string]string{"CLIENT_KEY": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))})
	if err := os.WriteFile(creds, data, 0o600); err != nil {
		t.Fatal(err)
	}
	federated := filepath.Join(dir, "federated")
	if err := os.WriteFile(federated, []byte("federated-token-text\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	head := []string{"--endpoint=https://records.example", "--paths=/read", "--methods=GET", "--credentials=" + creds,
		"--token-endpoint=" + tokenEndpoint.URL + "/token", "--client-id=client-7", "--token-only"}
	for _, c := range []struct {
		name  string
		extra []string
		code  int
		want  string
	}{
		{"an unknown algorithm", []string{"--assertion-key=CLIENT_KEY", "--assertion-alg=PS384"}, 1, "--assertion-alg is RS256 or PS256"},
		{"beside a federated token", []string{"--federated-token-file=" + federated, "--assertion-alg=PS256"}, 1, "--assertion-alg is the algorithm of an assertion this adapter signs, with --assertion-key"},
		{"PS256 beside a P-256 key", []string{"--assertion-key=CLIENT_KEY", "--assertion-alg=PS256"}, int(httpsource.TokenNoCredential), "the token step's key is EC P-256, which signs ES256; --assertion-alg=PS256 is for an RSA key"},
	} {
		var stdout, stderr bytes.Buffer
		code := run(append(append([]string(nil), head...), c.extra...), strings.NewReader(""), &stdout, &stderr)
		if code != c.code || !strings.Contains(stderr.String(), c.want) || stdout.Len() != 0 {
			t.Fatalf("%s: %d %q %q", c.name, code, stdout.String(), stderr.String())
		}
		if c.name == "an unknown algorithm" && strings.Contains(stderr.String(), "PS384") {
			t.Fatalf("the refusal repeats the value: %q", stderr.String())
		}
	}
	if tokenHits != 0 {
		t.Fatalf("%d token requests", tokenHits)
	}
}
