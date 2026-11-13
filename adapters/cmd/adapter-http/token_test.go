package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"adapters/httpsource"
)

// The command reports a token step's failure by its kind's exit status --
// 3 no credential, 4 the token request refused, 5 the source refused the
// token, 6 a sealed token it cannot open -- and --token-only writes the
// token sealed, never in the clear; an acquisition handed it in the
// environment sends it without a token request.
func TestRunReportsTheTokenStepByItsStatus(t *testing.T) {
	const issued = "issued-token-0123456789abcdef"
	refuse := false
	tokenHits := 0
	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenHits++
		r.ParseForm()
		if refuse || r.PostForm.Get("client_assertion") != "federated-token-text" {
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, `{"error":"invalid_client"}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"access_token":"`+issued+`","token_type":"Bearer","expires_in":600}`)
	}))
	defer tokenEndpoint.Close()
	accept := issued
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+accept {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"ok":true}`)
	}))
	defer source.Close()
	dir := t.TempDir()
	federated := filepath.Join(dir, "federated")
	if err := os.WriteFile(federated, []byte("federated-token-text\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	args := func(extra ...string) []string {
		return append([]string{"--endpoint=" + source.URL, "--paths=/read", "--methods=GET", "--token-endpoint=" + tokenEndpoint.URL + "/token",
			"--client-id=client-7", "--federated-token-file=" + federated}, extra...)
	}
	request := `{"path":"/read","method":"GET"}`
	runWith := func(argv []string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := run(argv, strings.NewReader(request), &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	code, out, errText := runWith(args("--token-only"))
	if code != 0 || strings.Contains(out, issued) {
		t.Fatalf("token only: %d %q %q", code, out, errText)
	}
	var sealed struct {
		Sealed    string `json:"sealed"`
		ExpiresIn int    `json:"expiresIn"`
	}
	if err := json.Unmarshal([]byte(out), &sealed); err != nil || sealed.ExpiresIn != 600 {
		t.Fatalf("token only's answer: %q %v", out, err)
	}
	t.Setenv(httpsource.SealedTokenVariable, sealed.Sealed)
	if code, out, errText := runWith(args()); code != 0 || !strings.Contains(out, `"ok":true`) || tokenHits != 1 {
		t.Fatalf("handed the sealed token: %d %q %q, %d token requests", code, out, errText, tokenHits)
	}
	accept = "another"
	if code, _, errText := runWith(args()); code != int(httpsource.TokenRejectedBySource) || strings.Contains(errText, issued) {
		t.Fatalf("the source refused the token: %d %q", code, errText)
	}
	t.Setenv(httpsource.SealedTokenVariable, "AAAA"+sealed.Sealed)
	if code, _, _ := runWith(args()); code != int(httpsource.TokenSealUnusable) {
		t.Fatalf("an unusable sealed token: %d", code)
	}
	refuse = true
	if code, _, errText := runWith(args("--token-only")); code != int(httpsource.TokenRefused) || strings.Contains(errText, "invalid_client") {
		t.Fatalf("the token request refused: %d %q", code, errText)
	}
	os.Remove(federated)
	before := tokenHits
	if code, _, _ := runWith(args("--token-only")); code != int(httpsource.TokenNoCredential) || tokenHits != before {
		t.Fatalf("no credential: %d, %d token requests", code, tokenHits-before)
	}
	if code, _, _ := runWith(args("--token-only", "--check")); code != 2 {
		t.Fatalf("--token-only with --check: %d", code)
	}
}
