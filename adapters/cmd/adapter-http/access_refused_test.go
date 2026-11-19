package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"adapters/httpsource"
)

// An endpoint's 401 or 403 exits 10 with the status and the listed code,
// or "unlisted", on stdout and the diagnostic on stderr it always had; a
// declared pair exits 8 with the pair; an undeclared one exits 1 as
// before; a token endpoint's 401 is a refused token request, exit 4, with
// nothing on stdout; and lists out of their form are refused before any
// request, exit 2.
func TestRunReportsAnAccessRefusalByItsStatus(t *testing.T) {
	var status int
	var body string
	var hits int
	answer := func(w http.ResponseWriter) {
		hits++
		w.WriteHeader(status)
		io.WriteString(w, body)
	}
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { answer(w) }))
	defer source.Close()
	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { answer(w) }))
	defer tokenEndpoint.Close()
	federated := filepath.Join(t.TempDir(), "federated")
	if err := os.WriteFile(federated, []byte("federated-token-text\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	codes := []string{"--error-code-at=error.code", "--expired-codes=400:resyncRequired", "--access-codes=Authorization_RequestDenied"}
	runWith := func(argv ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := run(append([]string{"--endpoint=" + source.URL, "--paths=/read", "--methods=GET"}, argv...), strings.NewReader(`{"path":"/read","method":"GET"}`), &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	for _, c := range []struct {
		status            int
		body              string
		exit              int
		report, diagnosed string
	}{
		{403, `{"error":{"code":"Authorization_RequestDenied"}}`, httpsource.AccessRefusedStatus, `{"accessRefused":{"code":"Authorization_RequestDenied","status":403}}`, "adapter-http: the endpoint answered 403 Forbidden: {\"error\":{\"code\":\"Authorization_RequestDenied\"}}\n"},
		{401, `{"error":{"code":"codeNotDeclared"}}`, httpsource.AccessRefusedStatus, `{"accessRefused":{"code":"unlisted","status":401}}`, "adapter-http: the endpoint answered 401 Unauthorized: {\"error\":{\"code\":\"codeNotDeclared\"}}\n"},
		{400, `{"error":{"code":"resyncRequired"}}`, httpsource.ReferenceExpiredStatus, `{"referenceExpired":{"code":"resyncRequired","status":400}}`, "adapter-http: the endpoint answered 400 Bad Request: {\"error\":{\"code\":\"resyncRequired\"}}\n"},
		{404, `{"error":{"code":"resyncRequired"}}`, 1, ``, "adapter-http: the endpoint answered 404 Not Found: {\"error\":{\"code\":\"resyncRequired\"}}\n"},
	} {
		status, body = c.status, c.body
		if code, out, diagnosed := runWith(codes...); code != c.exit || out != c.report || diagnosed != c.diagnosed {
			t.Fatalf("%d: exit %d, stdout %q, stderr %q", c.status, code, out, diagnosed)
		}
	}
	// With nothing declared, an access refusal is "unlisted" and a pair is
	// a refusing answer as before.
	status, body = http.StatusForbidden, `{"error":{"code":"Authorization_RequestDenied"}}`
	if code, out, _ := runWith(); code != httpsource.AccessRefusedStatus || out != `{"accessRefused":{"code":"unlisted","status":403}}` {
		t.Fatalf("nothing declared: exit %d, stdout %q", code, out)
	}
	status = http.StatusUnauthorized
	tokenOnly := []string{"--token-endpoint=" + tokenEndpoint.URL + "/token", "--client-id=client-7", "--federated-token-file=" + federated, "--token-only"}
	if code, out, diagnosed := runWith(append(codes, tokenOnly...)...); code != int(httpsource.TokenRefused) || out != "" || diagnosed != "adapter-http: token step: the token endpoint refused the token request (401)\n" {
		t.Fatalf("a token endpoint's 401: exit %d, stdout %q, stderr %q", code, out, diagnosed)
	}
	hits = 0
	for _, bad := range [][]string{
		{"--error-code-at=error.code"},
		{"--access-codes=Authorization_RequestDenied"},
		{"--error-code-at=error.code", "--access-codes=unlisted"},
		{"--error-code-at=error.code", "--expired-codes=410:resyncRequired"},
	} {
		if code, out, diagnosed := runWith(bad...); code != 2 || out != "" || !strings.HasPrefix(diagnosed, "adapter-http: --") {
			t.Fatalf("%q: exit %d, stdout %q, stderr %q", bad, code, out, diagnosed)
		}
	}
	if hits != 0 {
		t.Fatalf("a refused declaration reached the endpoint %d times", hits)
	}
}
