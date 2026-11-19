// Package metadataclient is the one client the adapters ask the platform's
// metadata server with: adapter-http's metadata token step (gateway #502,
// docs/adr/0043-a-federated-token-from-the-platforms-metadata-server.md)
// and adapter-gcp-asset's metadata token source (gateway #510). The address
// is built in, as an IP literal: no configuration member, flag or
// environment variable names it, no resolver is asked where it is, no proxy
// carries the request, the connection is dialed to it alone, and no
// redirect is followed.
package metadataclient

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"time"
)

// Address is the metadata server: the platform's fixed link-local address,
// written as an IP literal so that no resolver is asked where it is. Each
// caller's package holds it in a variable that only a test of that package
// points at a stand-in; nothing a configuration, a flag or the environment
// holds changes it.
const Address = "http://169.254.169.254"

// MaxHeaderBytes bounds an answer's header.
const MaxHeaderBytes = 64 << 10

// ErrAddress is a connection to an address other than the metadata
// server's, which the client does not make, and a base that is not an IP
// literal over http, for which no client is made.
var ErrAddress = errors.New("a connection to an address other than the metadata server's is not made")

// ErrRedirect is a redirect, which the client does not follow: it would be
// an answer from somewhere else.
var ErrRedirect = errors.New("the metadata server answered with a redirect, which is not followed")

// dial makes a connection once its address is the pinned one. A test of
// this package replaces it to see what would be dialed, so that no test
// connects to an address it did not mean to.
var dial = func(ctx context.Context, dialer *net.Dialer, network, address string) (net.Conn, error) {
	return dialer.DialContext(ctx, network, address)
}

// New is the client the metadata server at base is asked with: no proxy, a
// connection dialed to base's address and port alone, no redirect followed,
// the header bounded to MaxHeaderBytes, and the request bounded by timeout.
// base is Address, or a test's stand-in; one that is not http to an IP
// literal is ErrAddress, so a name is never resolved. The caller bounds the
// body it reads and holds the answer to Flavored.
func New(base string, timeout time.Duration) (*http.Client, error) {
	parsed, err := url.Parse(base)
	if err != nil || parsed.Scheme != "http" || net.ParseIP(parsed.Hostname()) == nil {
		return nil, ErrAddress
	}
	pinned := parsed.Host
	if parsed.Port() == "" {
		pinned = net.JoinHostPort(parsed.Hostname(), "80")
	}
	dialer := &net.Dialer{Timeout: timeout}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				if address != pinned {
					return nil, ErrAddress
				}
				return dial(ctx, dialer, network, address)
			},
			DisableKeepAlives:      true,
			MaxResponseHeaderBytes: MaxHeaderBytes,
			DisableCompression:     true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return ErrRedirect },
	}, nil
}

// Flavored reports whether an answer's header carries Metadata-Flavor:
// Google exactly once, so an answer from something else on that address is
// not taken.
func Flavored(header http.Header) bool {
	flavor := header.Values("Metadata-Flavor")
	return len(flavor) == 1 && flavor[0] == "Google"
}
