package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"adapters/httpsource"
)

// An answer of 429 or 503, from the source's endpoint or the token step's,
// exits 7 with the report on stdout and the diagnostic on stderr it always
// had; any other refusing answer exits as before, with nothing on stdout.
func TestRunReportsAThrottledAnswerByItsStatus(t *testing.T) {
	var status int
	var retryAfter string
	answer := func(w http.ResponseWriter) {
		if retryAfter != "" {
			w.Header().Set("Retry-After", retryAfter)
		}
		w.WriteHeader(status)
		io.WriteString(w, "busy")
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
	tokenOnly := []string{"--token-endpoint=" + tokenEndpoint.URL + "/token", "--client-id=client-7", "--federated-token-file=" + federated, "--token-only"}
	for _, c := range []struct {
		status            int
		retryAfter        string
		exit              int
		report, diagnosed string
		tokenExit         int
	}{
		{429, "30", 7, `{"throttled":{"retryAfter":30,"status":429}}`, "adapter-http: the endpoint answered 429 Too Many Requests: busy\n", 7},
		{503, "", 7, `{"throttled":{"retryAfter":null,"status":503}}`, "adapter-http: the endpoint answered 503 Service Unavailable: busy\n", 7},
		{503, "-1", 7, `{"throttled":{"retryAfter":null,"status":503}}`, "adapter-http: the endpoint answered 503 Service Unavailable: busy\n", 7},
		{502, "30", 1, ``, "adapter-http: the endpoint answered 502 Bad Gateway: busy\n", int(httpsource.TokenRefused)},
		{500, "30", 1, ``, "adapter-http: the endpoint answered 500 Internal Server Error: busy\n", int(httpsource.TokenRefused)},
	} {
		status, retryAfter = c.status, c.retryAfter
		if code, out, diagnosed := runWith(); code != c.exit || out != c.report || diagnosed != c.diagnosed {
			t.Fatalf("%d: exit %d, stdout %q, stderr %q", c.status, code, out, diagnosed)
		}
		wantToken := "adapter-http: token step: the token endpoint refused the token request (" + strconv.Itoa(c.status) + ")\n"
		if code, out, diagnosed := runWith(tokenOnly...); code != c.tokenExit || out != c.report || diagnosed != wantToken {
			t.Fatalf("%d, token step: exit %d, stdout %q, stderr %q", c.status, code, out, diagnosed)
		}
	}
}
