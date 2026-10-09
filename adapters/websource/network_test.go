package websource

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// memoryFixture runs one HTTP/1.1 request per in-memory TLS connection. It
// exercises the real transport without opening a listening socket.
func memoryFixture(t *testing.T, serve func(net.Conn, *http.Request)) fetcher {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		DNSNames:     []string{"example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	certificate := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	serverTLS := &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}

	var mu sync.Mutex
	var servers []net.Conn
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		for _, conn := range servers {
			conn.Close()
		}
	})
	return fetcher{
		tls: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		lookup: func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
		},
		dial: func(_ context.Context, _, address string) (net.Conn, error) {
			if address != "8.8.8.8:443" {
				return nil, errors.New("unexpected dial address")
			}
			client, server := net.Pipe()
			server.SetDeadline(time.Now().Add(time.Second))
			mu.Lock()
			servers = append(servers, server)
			mu.Unlock()
			go func() {
				conn := tls.Server(server, serverTLS)
				defer server.Close()
				if conn.Handshake() != nil {
					return
				}
				req, err := http.ReadRequest(bufio.NewReader(conn))
				if err == nil {
					serve(conn, req)
				}
			}()
			return client, nil
		},
	}
}

func TestDelayedResponseHeadersExceedDeadline(t *testing.T) {
	f := memoryFixture(t, func(conn net.Conn, _ *http.Request) {
		time.Sleep(250 * time.Millisecond)
		io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok")
	})
	f.network = networkOptions{responseHeaderTimeout: 50 * time.Millisecond, overallTimeout: time.Second}
	if _, err := f.read(context.Background(), "https://example.com/"); !errors.Is(err, ErrNetwork) {
		t.Fatal(err)
	}
}

func TestStalledBodyExceedsOverallDeadline(t *testing.T) {
	f := memoryFixture(t, func(conn net.Conn, _ *http.Request) {
		io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\npartial")
		var one [1]byte
		conn.Read(one[:])
	})
	f.network = networkOptions{responseHeaderTimeout: time.Second, overallTimeout: 50 * time.Millisecond}
	if _, err := f.read(context.Background(), "https://example.com/"); !errors.Is(err, ErrNetwork) {
		t.Fatal(err)
	}
}

func TestResponseHeadersOver64KiBAreRefused(t *testing.T) {
	f := memoryFixture(t, func(conn net.Conn, _ *http.Request) {
		io.WriteString(conn, "HTTP/1.1 200 OK\r\nX-Large: "+strings.Repeat("a", 65<<10)+"\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok")
	})
	if _, err := f.read(context.Background(), "https://example.com/"); !errors.Is(err, ErrNetwork) {
		t.Fatal(err)
	}
}

func TestRedirectChainExceedsOverallDeadline(t *testing.T) {
	var requests atomic.Int32
	f := memoryFixture(t, func(conn net.Conn, _ *http.Request) {
		requests.Add(1)
		time.Sleep(40 * time.Millisecond)
		io.WriteString(conn, "HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\n\r\n")
	})
	f.network = networkOptions{responseHeaderTimeout: time.Second, overallTimeout: 100 * time.Millisecond}
	if _, err := f.read(context.Background(), "https://example.com/start"); !errors.Is(err, ErrNetwork) {
		t.Fatal(err)
	}
	if got := requests.Load(); got >= 6 {
		t.Fatal("redirect chain reached request bound", got)
	}
}
