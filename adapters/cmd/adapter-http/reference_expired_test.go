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

// A 410 from the source's endpoint exits 8 with the report on stdout and
// the diagnostic on stderr it always had; a 404 or a 400 exits 1 as before,
// with nothing on stdout; a token endpoint's 410 is a refused token
// request, exit 4, with nothing on stdout.
func TestRunReportsAnExpiredReferenceByItsStatus(t *testing.T) {
	var status int
	answer := func(w http.ResponseWriter) {
		w.WriteHeader(status)
		io.WriteString(w, "gone")
	}
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { answer(w) }))
	defer source.Close()
	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { answer(w) }))
	defer tokenEndpoint.Close()
	federated := filepath.Join(t.TempDir(), "federated")
	if err := os.WriteFile(federated, []byte("federated-token-text\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runWith := func(argv ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := run(append([]string{"--endpoint=" + source.URL, "--paths=/read", "--methods=GET"}, argv...), strings.NewReader(`{"path":"/read","method":"GET"}`), &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	for _, c := range []struct {
		status            int
		exit              int
		report, diagnosed string
	}{
		{410, httpsource.ReferenceExpiredStatus, `{"referenceExpired":{"status":410}}`, "adapter-http: the endpoint answered 410 Gone: gone\n"},
		{404, 1, ``, "adapter-http: the endpoint answered 404 Not Found: gone\n"},
		{400, 1, ``, "adapter-http: the endpoint answered 400 Bad Request: gone\n"},
	} {
		status = c.status
		if code, out, diagnosed := runWith(); code != c.exit || out != c.report || diagnosed != c.diagnosed {
			t.Fatalf("%d: exit %d, stdout %q, stderr %q", c.status, code, out, diagnosed)
		}
	}
	status = http.StatusGone
	tokenOnly := []string{"--token-endpoint=" + tokenEndpoint.URL + "/token", "--client-id=client-7", "--federated-token-file=" + federated, "--token-only"}
	if code, out, diagnosed := runWith(tokenOnly...); code != int(httpsource.TokenRefused) || out != "" || diagnosed != "adapter-http: token step: the token endpoint refused the token request (410)\n" {
		t.Fatalf("a token endpoint's 410: exit %d, stdout %q, stderr %q", code, out, diagnosed)
	}
}
