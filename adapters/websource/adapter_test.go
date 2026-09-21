package websource

import (
	"adapters/attachment"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"testing"
)

func fixture(t *testing.T, h http.HandlerFunc) fetcher {
	t.Helper()
	s := httptest.NewTLSServer(h)
	t.Cleanup(s.Close)
	roots := x509.NewCertPool()
	roots.AddCert(s.Certificate())
	return fetcher{tls: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, lookup: func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	}, dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "8.8.8.8:443" {
			t.Errorf("unchecked dial %s", address)
		}
		return (&net.Dialer{}).DialContext(ctx, network, s.Listener.Addr().String())
	}}
}
func TestWebSnapshotAndRedirect(t *testing.T) {
	f := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Error("credential sent")
		}
		if r.URL.Path == "/start" {
			w.Header().Set("Set-Cookie", "secret=value")
			http.Redirect(w, r, "/article?view=1", 302)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(`<title>Example</title><script>secret code</script><style>bad css</style><h1>Policy</h1><p>First <b>fact</b> &amp; second.</p>`))
	})
	out, err := read(context.Background(), []byte(`{"url":"https://example.com/start"}`), f)
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Result      json.RawMessage
		Acquisition struct{ Endpoint, Snapshot, PeerIdentity string }
	}
	if json.Unmarshal(out, &envelope) != nil {
		t.Fatal("invalid envelope")
	}
	if err := attachment.Check(envelope.Result); err != nil {
		t.Fatal(err)
	}
	if filename := os.Getenv("JPACK_TEST_WEB_RECORD"); filename != "" {
		if err := os.WriteFile(filename, envelope.Result, 0600); err != nil {
			t.Fatal(err)
		}
	}
	var rec attachment.Record
	json.Unmarshal(envelope.Result, &rec)
	if rec.Provenance.Source.RequestedURL != "https://example.com/start" || rec.Provenance.Source.URL != "https://example.com/article?view=1" || rec.Provenance.Source.Format != "static-text-v1" || rec.Document.MediaType != "text/plain" || rec.Provenance.Source.Version != rec.Document.ID {
		t.Fatal("wrong source", string(envelope.Result))
	}
	text := rec.Content.Pages[0].Text
	if !strings.Contains(text, "First fact & second.") || strings.Contains(text, "secret") || strings.Contains(text, "bad css") {
		t.Fatal(text)
	}
	if envelope.Acquisition.Endpoint != "https://example.com/article" || envelope.Acquisition.Snapshot != rec.Provenance.Source.ResponseDigest || !strings.HasPrefix(envelope.Acquisition.PeerIdentity, "tls:sha256:") {
		t.Fatal("wrong acquisition")
	}
	rec.Provenance.Source.Format = "original-v1"
	raw, _ := json.Marshal(rec)
	if attachment.Check(raw) == nil {
		t.Fatal("mismatched original admitted")
	}
}
func TestPublicNetworkBoundary(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "10.0.0.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "192.0.2.1", "198.18.0.1", "224.0.0.1", "::1", "::ffff:127.0.0.1", "fc00::1", "fe80::1", "2001:db8::1", "2002:7f00:1::", "64:ff9b::a00:1"} {
		if publicAddress(netip.MustParseAddr(ip)) {
			t.Error("private admitted", ip)
		}
	}
	for _, raw := range []string{"http://example.com", "https://user:pass@example.com", "https://example.com:8443", "https://localhost", "https://host.internal", "https://127.0.0.1", "https://[::1]", "https://example.com/#x", "https://example.com\\@127.0.0.1", "file:///tmp/x"} {
		if _, err := admittedURL(raw); err == nil {
			t.Error("bad url admitted", raw)
		}
	}
	f := newFetcher()
	dialed := false
	f.dial = func(context.Context, string, string) (net.Conn, error) { dialed = true; return nil, errors.New("no") }
	f.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("10.0.0.1")}, nil
	}
	if _, err := f.dialPublic(context.Background(), "tcp", "example.com:443"); !errors.Is(err, ErrPrivate) || dialed {
		t.Fatal("mixed public/private DNS dialed")
	}
	f = fixture(t, func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "https://127.0.0.1/private", 302) })
	if _, err := f.read(context.Background(), "https://example.com"); !errors.Is(err, ErrPrivate) {
		t.Fatal(err)
	}
}
func TestRefusalsAndBounds(t *testing.T) {
	for _, raw := range []string{`{"url":"https://example.com","url":"https://example.com"}`, `{"URL":"https://example.com"}`, `{"url":"https://example.com","headers":{}}`, `null`} {
		if _, err := read(context.Background(), []byte(raw), fetcher{}); err == nil {
			t.Error("bad request", raw)
		}
	}
	for _, tc := range []struct {
		name, media, body string
		status            int
		want              error
	}{
		{"type", "application/json", "{}", 200, ErrMedia}, {"charset", "text/plain; charset=latin1", "body", 200, ErrMedia}, {"large", "text/plain", strings.Repeat("a", MaxBytes+1), 200, ErrLimit}, {"empty", "text/plain", "", 200, ErrLimit}, {"unauthorized", "text/plain", "private", 401, ErrNetwork},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := fixture(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", tc.media)
				w.WriteHeader(tc.status)
				w.Write([]byte(tc.body))
			})
			if _, err := f.read(context.Background(), "https://example.com"); !errors.Is(err, tc.want) {
				t.Fatal(err)
			}
		})
	}
	calls := 0
	f := fixture(t, func(w http.ResponseWriter, r *http.Request) { calls++; http.Redirect(w, r, "/again", 302) })
	if _, err := f.read(context.Background(), "https://example.com"); !errors.Is(err, ErrRedirect) || calls != 6 {
		t.Fatal(err, calls)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.read(ctx, "https://example.com"); err == nil {
		t.Fatal("cancel ignored")
	}
}
func TestPlainTextOriginal(t *testing.T) {
	f := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("Original text"))
	})
	out, err := read(context.Background(), []byte(`{"url":"https://example.com/policy.txt"}`), f)
	if err != nil {
		t.Fatal(err)
	}
	var env struct{ Result attachment.Record }
	json.Unmarshal(out, &env)
	s := env.Result.Provenance.Source
	if s.Format != "original-v1" || s.Version != s.ResponseDigest || s.Version != env.Result.Document.ID {
		t.Fatal(s)
	}
}

func TestPDFUsesLocalExtractionWithoutOCR(t *testing.T) {
	for _, name := range []string{"normal.pdf", "scanned.pdf"} {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile("../document/testdata/" + name)
			if err != nil {
				t.Fatal(err)
			}
			f := fixture(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/pdf")
				w.Write(raw)
			})
			out, err := read(context.Background(), []byte(`{"url":"https://example.com/file.pdf"}`), f)
			if err != nil {
				t.Fatal(err)
			}
			var env struct{ Result attachment.Record }
			if json.Unmarshal(out, &env) != nil {
				t.Fatal("bad result")
			}
			if env.Result.Provenance.OCR != nil || env.Result.Provenance.Source.Format != "original-v1" || env.Result.Document.ID != digest(raw) {
				t.Fatal("wrong PDF provenance")
			}
			if name == "scanned.pdf" && env.Result.Content.Chars != 0 {
				t.Fatal("invented scanned text")
			}
		})
	}
}
func TestRedirectResolvesAgainAndPinsTheCheckedAddress(t *testing.T) {
	f := fixture(t, func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "https://other.example.com/", 302) })
	calls := 0
	f.lookup = func(_ context.Context, network, host string) ([]netip.Addr, error) {
		calls++
		if host == "other.example.com" {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	}
	if _, err := f.read(context.Background(), "https://example.com/start"); !errors.Is(err, ErrPrivate) || calls != 2 {
		t.Fatal(err, calls)
	}
}
func TestCompressionAndBrokenUTF8AreNotSilentlyAccepted(t *testing.T) {
	f := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Encoding", "gzip")
		w.Write([]byte("not gzip"))
	})
	if _, err := f.read(context.Background(), "https://example.com"); !errors.Is(err, ErrMedia) {
		t.Fatal(err)
	}
	if _, _, err := staticText(context.Background(), []byte{255}); !errors.Is(err, ErrMedia) {
		t.Fatal(err)
	}
}

func TestTLSHostnameAndCertificateVerificationRemainRequired(t *testing.T) {
	f := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("text"))
	})
	if _, err := f.read(context.Background(), "https://example.net"); !errors.Is(err, ErrNetwork) {
		t.Fatal("wrong TLS host accepted", err)
	}
	f.tls = nil
	if _, err := f.read(context.Background(), "https://example.com"); !errors.Is(err, ErrNetwork) {
		t.Fatal("untrusted TLS certificate accepted", err)
	}
}
func TestNestedTemplatesAreOmitted(t *testing.T) {
	data, _, err := staticText(context.Background(), []byte(`<p>Visible</p><template><template>hidden</template>still hidden</template><svg/><p>After</p>`))
	if err != nil || strings.Contains(string(data), "hidden") || !strings.Contains(string(data), "After") {
		t.Fatal(string(data), err)
	}
}
