//go:build gateway_acquisition_fixture

// Package acquisitionfixture is linked only into the explicitly tagged test
// harness. Its fixed virtual hosts never resolve or dial outside loopback.
package acquisitionfixture

import (
	"adapters/document"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

const PageHost = "example.com"
const SearchHost = "api.tavily.com"
const SearchEndpoint = "https://" + SearchHost + "/search"
const Credential = "tvly-fixture-only"

var ErrNetwork = errors.New("fixture-network-refused")

// ErrBuild is the refusal of a program that is not marked as the fixture. Only
// the builder stamps the marker, so a plain tagged build refuses by itself.
var ErrBuild = errors.New("fixture-build-required")

// Marked reports whether this program was built as the fixture: its reported
// version begins "fixture.", as the builder stamps it.
func Marked() bool { return strings.HasPrefix(document.Version, "fixture.") }

// Network serves only the compiled synthetic corpus. No request, environment
// variable or operator argument can supply a destination, root or response.
type Network struct {
	server *http.Server
	addr   string
	roots  *x509.CertPool
}

func New() (*Network, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, ErrNetwork
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Gateway acquisition fixture"}, DNSNames: []string{PageHost, SearchHost}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, ErrNetwork
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, ErrNetwork
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, ErrNetwork
	}
	n := &Network{addr: listener.Addr().String(), roots: x509.NewCertPool()}
	n.roots.AddCert(leaf)
	n.server = &http.Server{Handler: http.HandlerFunc(serve), ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: time.Second, MaxHeaderBytes: 32 << 10, ErrorLog: log.New(io.Discard, "", 0)}
	tlsListener := tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12})
	go func() { _ = n.server.Serve(tlsListener) }()
	return n, nil
}

func (n *Network) Close() { _ = n.server.Close() }

func (n *Network) TLSConfig() *tls.Config {
	return &tls.Config{RootCAs: n.roots.Clone(), MinVersion: tls.VersionTLS12}
}

// LookupNetIP replaces only the page reader's DNS dependency. The production
// public-address admission and numeric-address dial checks still execute.
func (n *Network) LookupNetIP(_ context.Context, network, host string) ([]netip.Addr, error) {
	if network != "ip" || host != PageHost {
		return nil, ErrNetwork
	}
	return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
}

func (n *Network) DialPage(ctx context.Context, network, address string) (net.Conn, error) {
	if address != "8.8.8.8:443" {
		return nil, ErrNetwork
	}
	return n.dial(ctx, network)
}

func (n *Network) dial(ctx context.Context, network string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" {
		return nil, ErrNetwork
	}
	return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp4", n.addr)
}

type searchTransport struct{ transport *http.Transport }

func (t searchTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.String() != SearchEndpoint || r.Method != http.MethodPost {
		return nil, ErrNetwork
	}
	return t.transport.RoundTrip(r)
}

// SearchClient retains the real provider URL and verified TLS hostname. It
// cannot contact OAuth, another provider, a redirect or an environment proxy.
func (n *Network) SearchClient() (*http.Client, func()) {
	transport := &http.Transport{Proxy: nil, TLSClientConfig: n.TLSConfig(), DisableKeepAlives: true, DisableCompression: true, MaxResponseHeaderBytes: 32 << 10, TLSHandshakeTimeout: 2 * time.Second, ResponseHeaderTimeout: 5 * time.Second, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != SearchHost+":443" {
			return nil, ErrNetwork
		}
		return n.dial(ctx, network)
	}}
	return &http.Client{Transport: searchTransport{transport}, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, transport.CloseIdleConnections
}
