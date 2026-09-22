// Package websource reads one explicitly selected public HTTPS URL. It has no
// account, cookie jar, proxy, browser script engine, or provider credential.
package websource

import (
	"adapters/attachment"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

const MaxBytes = 4 << 20
const MaxOutput = 16 << 20
const Timeout = 45 * time.Second

var ErrURL = errors.New("web-invalid-url")
var ErrNetwork = errors.New("web-unavailable")
var ErrPrivate = errors.New("web-public-only")
var ErrLimit = errors.New("web-over-limit")
var ErrMedia = errors.New("web-unsupported-type")
var ErrRedirect = errors.New("web-redirect-limit")

var excluded = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001::/23"), netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2002::/16"), netip.MustParsePrefix("3fff::/20"),
}
var publicV6 = netip.MustParsePrefix("2000::/3")

func publicAddress(ip netip.Addr) bool {
	if !ip.IsValid() || ip.Zone() != "" {
		return false
	}
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.Is6() && !publicV6.Contains(ip) {
		return false
	}
	for _, block := range excluded {
		if block.Contains(ip) {
			return false
		}
	}
	return true
}
func admittedURL(raw string) (*url.URL, error) {
	u, ok := attachment.WebURL(raw)
	if !ok {
		return nil, ErrURL
	}
	host := strings.ToLower(u.Hostname())
	if ip, err := netip.ParseAddr(host); err == nil {
		if !publicAddress(ip) {
			return nil, ErrPrivate
		}
		return u, nil
	}
	if len(host) > 253 || !strings.Contains(host, ".") || strings.HasSuffix(host, ".") {
		return nil, ErrPrivate
	}
	for _, suffix := range []string{".localhost", ".local", ".internal", ".lan", ".home", ".test", ".invalid", ".onion"} {
		if strings.HasSuffix(host, suffix) {
			return nil, ErrPrivate
		}
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return nil, ErrURL
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return nil, ErrURL
			}
		}
	}
	return u, nil
}

type fetcher struct {
	lookup func(context.Context, string, string) ([]netip.Addr, error)
	dial   func(context.Context, string, string) (net.Conn, error)
	tls    *tls.Config // nil in production; test roots only, never an operator flag.
}

func newFetcher() fetcher {
	return fetcher{lookup: net.DefaultResolver.LookupNetIP, dial: (&net.Dialer{Timeout: 8 * time.Second}).DialContext}
}
func (f fetcher) dialPublic(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || port != "443" {
		return nil, ErrURL
	}
	var ips []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		ips = []netip.Addr{ip}
	} else {
		ips, err = f.lookup(ctx, "ip", host)
		if err != nil {
			return nil, ErrNetwork
		}
	}
	if len(ips) == 0 || len(ips) > 16 {
		return nil, ErrPrivate
	}
	for _, ip := range ips {
		if !publicAddress(ip) {
			return nil, ErrPrivate
		}
	}
	// The checked numeric address is the exact dial target. DNS is never repeated
	// by the transport, while HTTP Host and TLS ServerName remain the URL's host.
	for i, ip := range ips {
		if i == 4 {
			break
		}
		conn, err := f.dial(ctx, network, net.JoinHostPort(ip.Unmap().String(), port))
		if err == nil {
			return conn, nil
		}
		if ctx.Err() != nil {
			return nil, ErrNetwork
		}
	}
	return nil, ErrNetwork
}

type response struct {
	raw   []byte
	media string
	url   string
	tls   *tls.ConnectionState
}

func (f fetcher) read(ctx context.Context, rawURL string) (response, error) {
	current, err := admittedURL(rawURL)
	if err != nil {
		return response{}, err
	}
	transport := &http.Transport{Proxy: nil, DialContext: f.dialPublic, TLSClientConfig: f.tls, DisableKeepAlives: true, DisableCompression: true, MaxResponseHeaderBytes: 32 << 10, TLSHandshakeTimeout: 8 * time.Second, ResponseHeaderTimeout: 10 * time.Second}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for redirects := 0; redirects <= 5; redirects++ {
		req, err := http.NewRequestWithContext(ctx, "GET", current.String(), nil)
		if err != nil {
			return response{}, ErrURL
		}
		req.Header.Set("Accept", "text/html, text/plain, application/pdf")
		req.Header.Set("Accept-Encoding", "identity")
		req.Header.Set("User-Agent", "Judgment-Pack-Web/1")
		res, err := client.Do(req)
		if err != nil {
			if errors.Is(err, ErrPrivate) {
				return response{}, ErrPrivate
			}
			return response{}, ErrNetwork
		}
		if res.StatusCode == 301 || res.StatusCode == 302 || res.StatusCode == 303 || res.StatusCode == 307 || res.StatusCode == 308 {
			location := res.Header.Get("Location")
			res.Body.Close()
			if len(location) == 0 || len(location) > 4096 {
				return response{}, ErrURL
			}
			next, err := current.Parse(location)
			if err != nil {
				return response{}, ErrURL
			}
			current, err = admittedURL(next.String())
			if err != nil {
				return response{}, err
			}
			continue
		}
		if res.StatusCode != 200 || res.TLS == nil || len(res.TLS.VerifiedChains) == 0 {
			res.Body.Close()
			return response{}, ErrNetwork
		}
		media, params, err := mime.ParseMediaType(res.Header.Get("Content-Type"))
		if err != nil || media != "text/html" && media != "text/plain" && media != "application/pdf" || params["charset"] != "" && !strings.EqualFold(params["charset"], "utf-8") && !strings.EqualFold(params["charset"], "us-ascii") {
			res.Body.Close()
			return response{}, ErrMedia
		}
		if encoding := res.Header.Get("Content-Encoding"); encoding != "" && !strings.EqualFold(encoding, "identity") {
			res.Body.Close()
			return response{}, ErrMedia
		}
		if res.ContentLength > MaxBytes {
			res.Body.Close()
			return response{}, ErrLimit
		}
		raw, err := io.ReadAll(io.LimitReader(res.Body, MaxBytes+1))
		res.Body.Close()
		if err != nil || ctx.Err() != nil {
			return response{}, ErrNetwork
		}
		if len(raw) == 0 || len(raw) > MaxBytes {
			return response{}, ErrLimit
		}
		return response{raw, media, current.String(), res.TLS}, nil
	}
	return response{}, ErrRedirect
}
