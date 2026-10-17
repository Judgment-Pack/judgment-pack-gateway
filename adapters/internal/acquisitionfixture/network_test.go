//go:build gateway_acquisition_fixture

package acquisitionfixture

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestFixtureNetworkHasNoExternalFallback(t *testing.T) {
	n, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	for _, host := range []string{"api.tavily.com", "unrouted.example.org", "localhost", "127.0.0.1", "8.8.8.8"} {
		if _, err := n.LookupNetIP(t.Context(), "ip", host); !errors.Is(err, ErrNetwork) {
			t.Fatal("unrouted DNS admitted", host, err)
		}
	}
	for _, target := range []string{"8.8.8.8:80", "1.1.1.1:443", "127.0.0.1:443", "example.com:443"} {
		if conn, err := n.DialPage(t.Context(), "tcp", target); !errors.Is(err, ErrNetwork) || conn != nil {
			t.Fatal("unchecked dial admitted", target, err)
		}
	}
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	client, closeClient := n.SearchClient()
	defer closeClient()
	for _, endpoint := range []string{"https://example.com/search", "http://api.tavily.com/search", "https://api.tavily.com/search?x=1", "https://api.tavily.com/other", "https://api.tavily.com:8443/search", "https://oauth2.googleapis.com/token"} {
		req, _ := http.NewRequestWithContext(t.Context(), "POST", endpoint, strings.NewReader(`{}`))
		if response, err := client.Do(req); !errors.Is(err, ErrNetwork) || response != nil {
			t.Fatal("unrouted endpoint admitted", endpoint, err)
		}
	}
	req, _ := http.NewRequestWithContext(t.Context(), "POST", SearchEndpoint, strings.NewReader(`{"query":"fixture","max_results":3}`))
	req.Header.Set("Authorization", "Bearer "+Credential)
	response, err := client.Do(req)
	if err != nil {
		t.Fatal("fixture used environment proxy", err)
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(response.Body)
	if response.StatusCode != 200 || response.TLS == nil || len(response.TLS.VerifiedChains) == 0 || !strings.Contains(string(data), CompanyURL) {
		t.Fatal("fixture HTTPS response missing", response.StatusCode)
	}
}

func TestFixtureTLSVerifiesHostnameAndRoots(t *testing.T) {
	n, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	for _, name := range []string{PageHost, SearchHost, "wrong.example.org"} {
		config := n.TLSConfig()
		config.ServerName = name
		conn, err := (&tls.Dialer{NetDialer: &net.Dialer{Timeout: time.Second}, Config: config}).DialContext(t.Context(), "tcp4", n.addr)
		if name == "wrong.example.org" {
			if err == nil {
				conn.Close()
				t.Fatal("wrong TLS hostname admitted")
			}
		} else if err != nil {
			t.Fatal("fixture hostname failed", err)
		} else {
			conn.Close()
		}
	}
	config := &tls.Config{ServerName: PageHost, MinVersion: tls.VersionTLS12}
	if conn, err := (&tls.Dialer{Config: config}).DialContext(context.Background(), "tcp4", n.addr); err == nil {
		conn.Close()
		t.Fatal("fixture certificate trusted without explicit root")
	}
}

func TestFixtureIsAbsentFromOrdinaryAdapterBuilds(t *testing.T) {
	cmd := exec.CommandContext(t.Context(), "go", "list", "-buildvcs=false", "-deps", "-f", `{{.ImportPath}} {{join .GoFiles " "}}`, "./cmd/adapter-web", "./cmd/adapter-sources")
	cmd.Dir = "../.."
	cmd.Env = append(os.Environ(), "GOFLAGS=", "GOWORK=off", "GOPROXY=off")
	raw, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatal("ordinary adapter dependency inspection failed", err, string(raw))
	}
	if strings.Contains(string(raw), "acquisitionfixture") || strings.Contains(string(raw), "acquisition_fixture.go") {
		t.Fatal("fixture code reached an ordinary adapter build")
	}
}
