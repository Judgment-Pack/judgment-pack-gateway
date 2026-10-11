package websource

import (
	"adapters/attachment"
	"adapters/connections"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// A synthetic grounding result. The token is invented; no live link is used.
const groundingURL = "https://vertexaisearch.cloud.google.com/grounding-api-redirect/AUZIYQ-synthetic_Token0"
const groundingOrigin = "https://vertexaisearch.cloud.google.com"

// hit is one request a virtual host received, with the headers no hop may
// carry.
type hit struct{ host, path, cookie, authorization, referer string }

type hits struct {
	mu   sync.Mutex
	list []hit
}

func (h *hits) all() []hit {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]hit{}, h.list...)
}
func (h *hits) to(host string) int {
	n := 0
	for _, one := range h.all() {
		if one.host == host {
			n++
		}
	}
	return n
}

// hostsFixture serves several virtual hosts from one local TLS server, under
// one certificate naming them all, behind synthetic DNS: every name in routes
// resolves to a public address that the dialer maps to the local server, and
// a name in private resolves to the addresses given there, which the adapter
// must refuse before dialing. Nothing leaves the machine.
func hostsFixture(t *testing.T, routes map[string]http.HandlerFunc, private map[string][]string) (fetcher, *hits) {
	t.Helper()
	names := []string{}
	for host := range routes {
		names = append(names, host)
	}
	for host := range private {
		names = append(names, host)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture"}, DNSNames: names, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	log := &hits{}
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := strings.ToLower(r.Host)
		log.mu.Lock()
		log.list = append(log.list, hit{host, r.URL.RequestURI(), r.Header.Get("Cookie"), r.Header.Get("Authorization"), r.Header.Get("Referer")})
		log.mu.Unlock()
		route, ok := routes[host]
		if !ok {
			t.Errorf("request to an unrouted host %s", host)
			w.WriteHeader(404)
			return
		}
		route(w, r)
	}))
	s.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}
	s.StartTLS()
	t.Cleanup(s.Close)
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	return fetcher{tls: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, lookup: func(_ context.Context, _, host string) ([]netip.Addr, error) {
		if answers, ok := private[strings.ToLower(host)]; ok {
			out := []netip.Addr{}
			for _, a := range answers {
				out = append(out, netip.MustParseAddr(a))
			}
			return out, nil
		}
		if _, ok := routes[strings.ToLower(host)]; ok {
			return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
		}
		return nil, errors.New("no such host")
	}, dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "8.8.8.8:443" {
			t.Errorf("unchecked dial %s", address)
			return nil, errors.New("refused")
		}
		return (&net.Dialer{}).DialContext(ctx, network, s.Listener.Addr().String())
	}}, log
}

// redirect answers 302 to location, offering a cookie no later hop may send.
func redirect(location string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "provider-session=secret")
		w.Header().Set("Location", location)
		w.WriteHeader(302)
	}
}

// publisher redirects /report to /final on its own origin and serves a page.
func publisher(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/report":
			http.Redirect(w, r, "/final", 302)
		case "/final":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write([]byte(`<title>Annual report</title><p>The publisher's own text.</p>`))
		default:
			t.Errorf("unexpected publisher path %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}
}

func grounding() Options {
	return Options{RedirectPolicies: []string{connections.GoogleGroundingPolicy}}
}
func request(url string) []byte {
	raw, _ := json.Marshal(map[string]string{"url": url})
	return raw
}

// Unconfigured, the grounding redirect is refused as #224 refuses every hop to
// another origin: one request, the publisher never contacted. The refusal
// names the two origins and the policy that would follow the hop, and says it
// is not permitted.
func TestGroundingRedirectIsRefusedByDefault(t *testing.T) {
	f, log := hostsFixture(t, map[string]http.HandlerFunc{
		"vertexaisearch.cloud.google.com": redirect("https://example.com/report"),
		"example.com":                     publisher(t),
	}, nil)
	_, err := read(context.Background(), request(groundingURL), f)
	var refusal *RedirectRefusal
	if !errors.Is(err, ErrRedirectOrigin) || err.Error() != "web-redirect-origin" || !errors.As(err, &refusal) {
		t.Fatal(err)
	}
	if n := len(log.all()); n != 1 || log.to("example.com") != 0 {
		t.Fatal("requests", log.all())
	}
	if refusal.From != groundingOrigin || refusal.To != "https://example.com" || refusal.Policy != connections.GoogleGroundingPolicy {
		t.Fatalf("%+v", refusal)
	}
	line := RefusalLine(err)
	if line != `web-redirect-origin {"redirect":{"from":"https://vertexaisearch.cloud.google.com","permitted":false,"policy":"google-grounding","to":"https://example.com"}}` {
		t.Fatal(line)
	}
	for _, private := range []string{"grounding-api-redirect", "AUZIYQ", "report", "secret"} {
		if strings.Contains(line, private) {
			t.Fatal("the refusal quotes", private)
		}
	}
}

// Enabled by the operator, the same read follows the one hop, then a
// same-origin redirect at the publisher, and records both URLs and the
// policy. No hop carries a cookie, a credential or a referrer.
func TestGroundingRedirectIsFollowedOnceWhenTheOperatorEnablesIt(t *testing.T) {
	f, log := hostsFixture(t, map[string]http.HandlerFunc{
		"vertexaisearch.cloud.google.com": redirect("https://example.com/report"),
		"example.com":                     publisher(t),
	}, nil)
	out, err := readOptions(context.Background(), request(groundingURL), f, grounding())
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Result      json.RawMessage
		Acquisition struct{ Endpoint, Statement string }
	}
	if json.Unmarshal(out, &envelope) != nil || attachment.Check(envelope.Result) != nil {
		t.Fatal("invalid record", attachment.Check(envelope.Result))
	}
	if filename := os.Getenv("JPACK_TEST_WEB_REDIRECT_RECORD"); filename != "" {
		if err := os.WriteFile(filename, envelope.Result, 0600); err != nil {
			t.Fatal(err)
		}
	}
	var rec attachment.Record
	json.Unmarshal(envelope.Result, &rec)
	s := rec.Provenance.Source
	if s.RequestedURL != groundingURL || s.URL != "https://example.com/final" || s.RedirectPolicy != "google-grounding" || !strings.Contains(rec.Content.Pages[0].Text, "The publisher's own text.") {
		t.Fatalf("%+v", s)
	}
	// The statement keeps its three members; the policy is in the record.
	if envelope.Acquisition.Statement != `{"method":"GET","requestedUrl":"`+groundingURL+`","url":"https://example.com/final"}` || envelope.Acquisition.Endpoint != "https://example.com/final" {
		t.Fatal(envelope.Acquisition)
	}
	// The producer's check holds the member to what the policy can have done.
	for name, change := range map[string]func(source map[string]any){
		"an unknown policy":      func(s map[string]any) { s["redirectPolicy"] = "any-origin" },
		"an empty policy":        func(s map[string]any) { s["redirectPolicy"] = "" },
		"no change of host":      func(s map[string]any) { s["url"] = "https://vertexaisearch.cloud.google.com/final" },
		"another requested host": func(s map[string]any) { s["requestedUrl"] = "https://example.org/grounding-api-redirect/AUZIYQ" },
		// The grounding host, but never the endpoint: the policy cannot
		// have followed a hop from these.
		"an unrelated path": func(s map[string]any) { s["requestedUrl"] = "https://vertexaisearch.cloud.google.com/unrelated" },
		"an empty token": func(s map[string]any) {
			s["requestedUrl"] = "https://vertexaisearch.cloud.google.com/grounding-api-redirect/"
		},
		"a query": func(s map[string]any) { s["requestedUrl"] = groundingURL + "?q=1" },
	} {
		var record map[string]any
		json.Unmarshal(envelope.Result, &record)
		change(record["provenance"].(map[string]any)["source"].(map[string]any))
		raw, _ := json.Marshal(record)
		if err := attachment.Check(raw); err == nil || !strings.Contains(err.Error(), "web-source") {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A record without the member is read as before, a cross-origin one
	// written before #224 included.
	var record map[string]any
	json.Unmarshal(envelope.Result, &record)
	delete(record["provenance"].(map[string]any)["source"].(map[string]any), "redirectPolicy")
	if raw, _ := json.Marshal(record); attachment.Check(raw) != nil {
		t.Error(attachment.Check(raw))
	}
	all := log.all()
	if len(all) != 3 || all[0].host != "vertexaisearch.cloud.google.com" || all[1].path != "/report" || all[2].path != "/final" {
		t.Fatal(all)
	}
	for _, one := range all {
		if one.cookie != "" || one.authorization != "" || one.referer != "" {
			t.Fatalf("a hop carried a header it must not: %+v", one)
		}
	}
}

// A record read without a policy hop is byte for byte what it was: no
// redirectPolicy member.
func TestASameOriginReadRecordsNoRedirectPolicy(t *testing.T) {
	f, _ := hostsFixture(t, map[string]http.HandlerFunc{"example.com": publisher(t)}, nil)
	out, err := readOptions(context.Background(), request("https://example.com/report"), f, grounding())
	if err != nil || strings.Contains(string(out), "redirectPolicy") {
		t.Fatal(err)
	}
}

// Every hop the policy does not cover keeps its refusal and its token, with
// the policy enabled. A policy refusal carries the origins and no policy (no
// supported policy would follow it); a hard refusal carries no member at all.
func TestRedirectPolicyRefusals(t *testing.T) {
	const other = "https://vertexaisearch.cloud.google.com/grounding-api-redirect/AUZIYQ-second"
	for _, c := range []struct {
		name, url string
		routes    map[string]http.HandlerFunc
		private   map[string][]string
		want      error
		requests  int
		from, to  string // a policy refusal's origins; empty for a hard refusal
	}{
		{"ordinary site", "https://example.com/start", map[string]http.HandlerFunc{"example.com": redirect("https://other.example.org/page")}, nil, ErrRedirectOrigin, 1, "https://example.com", "https://other.example.org"},
		{"wrong path", "https://vertexaisearch.cloud.google.com/grounding-api/AUZIYQ", nil, nil, ErrRedirectOrigin, 1, groundingOrigin, "https://example.com"},
		{"prefix without its slash", "https://vertexaisearch.cloud.google.com/grounding-api-redirect", nil, nil, ErrRedirectOrigin, 1, groundingOrigin, "https://example.com"},
		{"prefix deeper in the path", "https://vertexaisearch.cloud.google.com/x/grounding-api-redirect/AUZIYQ", nil, nil, ErrRedirectOrigin, 1, groundingOrigin, "https://example.com"},
		{"empty token", "https://vertexaisearch.cloud.google.com/grounding-api-redirect/", nil, nil, ErrRedirectOrigin, 1, groundingOrigin, "https://example.com"},
		{"two segments", "https://vertexaisearch.cloud.google.com/grounding-api-redirect/a/b", nil, nil, ErrRedirectOrigin, 1, groundingOrigin, "https://example.com"},
		{"encoded segment", "https://vertexaisearch.cloud.google.com/grounding-api-redirect/a%2Fb", nil, nil, ErrRedirectOrigin, 1, groundingOrigin, "https://example.com"},
		{"dot segment", "https://vertexaisearch.cloud.google.com/grounding-api-redirect/..", nil, nil, ErrRedirectOrigin, 1, groundingOrigin, "https://example.com"},
		{"query", groundingURL + "?q=1", nil, nil, ErrRedirectOrigin, 1, groundingOrigin, "https://example.com"},
		{"empty query", groundingURL + "?", nil, nil, ErrRedirectOrigin, 1, groundingOrigin, "https://example.com"},
		{"lookalike suffix", "https://vertexaisearch.cloud.google.com.example.org/grounding-api-redirect/AUZIYQ", map[string]http.HandlerFunc{"vertexaisearch.cloud.google.com.example.org": redirect("https://example.com/report")}, nil, ErrRedirectOrigin, 1, "https://vertexaisearch.cloud.google.com.example.org", "https://example.com"},
		{"lookalike hyphen", "https://vertexaisearch-cloud.google.com/grounding-api-redirect/AUZIYQ", map[string]http.HandlerFunc{"vertexaisearch-cloud.google.com": redirect("https://example.com/report")}, nil, ErrRedirectOrigin, 1, "https://vertexaisearch-cloud.google.com", "https://example.com"},
		{"subdomain", "https://evil.vertexaisearch.cloud.google.com/grounding-api-redirect/AUZIYQ", map[string]http.HandlerFunc{"evil.vertexaisearch.cloud.google.com": redirect("https://example.com/report")}, nil, ErrRedirectOrigin, 1, "https://evil.vertexaisearch.cloud.google.com", "https://example.com"},
		{"host spelled otherwise", "https://VERTEXAISEARCH.cloud.google.com/grounding-api-redirect/AUZIYQ", nil, nil, ErrRedirectOrigin, 1, groundingOrigin, "https://example.com"},
		{"second cross-origin hop", groundingURL, map[string]http.HandlerFunc{"example.com": redirect("https://other.example.org/page")}, nil, ErrRedirectOrigin, 2, "https://example.com", "https://other.example.org"},
		{"return to the provider", groundingURL, map[string]http.HandlerFunc{"example.com": redirect(other)}, nil, ErrRedirectOrigin, 2, "https://example.com", groundingOrigin},
		{"not the first redirect", groundingURL, map[string]http.HandlerFunc{"vertexaisearch.cloud.google.com": func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/grounding-api-redirect/AUZIYQ-second" {
				redirect("https://example.com/report")(w, r)
				return
			}
			redirect(other)(w, r)
		}}, nil, ErrRedirectOrigin, 2, groundingOrigin, "https://example.com"},
		{"http", groundingURL, map[string]http.HandlerFunc{"vertexaisearch.cloud.google.com": redirect("http://example.com/report")}, nil, ErrURL, 1, "", ""},
		{"another port", groundingURL, map[string]http.HandlerFunc{"vertexaisearch.cloud.google.com": redirect("https://example.com:8443/report")}, nil, ErrURL, 1, "", ""},
		{"credentials", groundingURL, map[string]http.HandlerFunc{"vertexaisearch.cloud.google.com": redirect("https://user:pass@example.com/report")}, nil, ErrURL, 1, "", ""},
		{"private literal", groundingURL, map[string]http.HandlerFunc{"vertexaisearch.cloud.google.com": redirect("https://10.0.0.1/report")}, nil, ErrPrivate, 1, "", ""},
		{"private suffix", groundingURL, map[string]http.HandlerFunc{"vertexaisearch.cloud.google.com": redirect("https://example.test/report")}, nil, ErrPrivate, 1, "", ""},
		{"private DNS answer", groundingURL, map[string]http.HandlerFunc{"vertexaisearch.cloud.google.com": redirect("https://private.example.com/report")}, map[string][]string{"private.example.com": {"10.0.0.7"}}, ErrPrivate, 1, "", ""},
		{"mixed DNS answers", groundingURL, map[string]http.HandlerFunc{"vertexaisearch.cloud.google.com": redirect("https://private.example.com/report")}, map[string][]string{"private.example.com": {"8.8.8.8", "10.0.0.7"}}, ErrPrivate, 1, "", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			routes := map[string]http.HandlerFunc{
				"vertexaisearch.cloud.google.com": redirect("https://example.com/report"),
				"example.com":                     publisher(t),
				"other.example.org":               func(http.ResponseWriter, *http.Request) { t.Error("a second origin was contacted") },
			}
			for host, route := range c.routes {
				routes[host] = route
			}
			f, log := hostsFixture(t, routes, c.private)
			_, err := readOptions(context.Background(), request(c.url), f, grounding())
			if !errors.Is(err, c.want) || len(log.all()) != c.requests {
				t.Fatal(err, log.all())
			}
			var refusal *RedirectRefusal
			if c.from == "" {
				if errors.As(err, &refusal) || RefusalLine(err) != c.want.Error() {
					t.Fatal("a hard refusal carried a redirect member", RefusalLine(err))
				}
				return
			}
			if !errors.As(err, &refusal) || refusal.From != c.from || refusal.To != c.to || refusal.Policy != "" {
				t.Fatalf("%+v", refusal)
			}
			if !strings.HasSuffix(RefusalLine(err), `"permitted":false,"policy":null,"to":"`+c.to+`"}}`) {
				t.Fatal(RefusalLine(err))
			}
		})
	}
}

// A site-scoped read and discovery are held to one origin and follow no
// policy hop, whatever the operator enabled; a refusal there names no policy.
func TestSiteScopedReadsAndDiscoveryFollowNoPolicyHop(t *testing.T) {
	routes := map[string]http.HandlerFunc{
		"vertexaisearch.cloud.google.com": func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/robots.txt" {
				w.WriteHeader(404)
				return
			}
			redirect("https://example.com/report")(w, r)
		},
		"example.com": func(http.ResponseWriter, *http.Request) { t.Error("the publisher was contacted") },
	}
	f, log := hostsFixture(t, routes, nil)
	raw, _ := json.Marshal(map[string]string{"url": groundingURL, "site": groundingOrigin + "/"})
	_, err := readOptions(context.Background(), raw, f, grounding())
	var refusal *RedirectRefusal
	if !errors.As(err, &refusal) || refusal.Policy != "" || log.to("vertexaisearch.cloud.google.com") != 2 || log.to("example.com") != 0 {
		t.Fatal(err, log.all())
	}
	f, log = hostsFixture(t, routes, nil)
	result := discoveryResult(t, request(groundingURL), f)
	if result.Pages[0].Status != "blocked" || result.Pages[0].Reason != "web-redirect-origin" || log.to("example.com") != 0 {
		t.Fatal(result.Pages, log.all())
	}
}

// Nothing in a request names a policy: a request that tries is refused
// before any request is made, as any request with another member is.
func TestARequestCannotEnableARedirectPolicy(t *testing.T) {
	f, log := hostsFixture(t, map[string]http.HandlerFunc{
		"vertexaisearch.cloud.google.com": redirect("https://example.com/report"),
		"example.com":                     publisher(t),
	}, nil)
	for _, raw := range []string{
		`{"url":"` + groundingURL + `","redirectPolicies":["google-grounding"]}`,
		`{"redirectPolicy":"google-grounding","url":"` + groundingURL + `"}`,
		`{"policy":"google-grounding","url":"` + groundingURL + `"}`,
		`{"site":"https://vertexaisearch.cloud.google.com/","url":"` + groundingURL + `","redirectPolicies":"google-grounding"}`,
	} {
		if _, err := read(context.Background(), []byte(raw), f); !errors.Is(err, ErrRequest) {
			t.Fatal(raw, err)
		}
	}
	if len(log.all()) != 0 {
		t.Fatal(log.all())
	}
}

// Configuration is read for each read, and the adapter runs once per
// acquisition: without the policy, the next read is refused as before.
func TestRevokingThePolicyRestoresTheDefault(t *testing.T) {
	f, log := hostsFixture(t, map[string]http.HandlerFunc{
		"vertexaisearch.cloud.google.com": redirect("https://example.com/report"),
		"example.com":                     publisher(t),
	}, nil)
	if _, err := readOptions(context.Background(), request(groundingURL), f, grounding()); err != nil {
		t.Fatal(err)
	}
	if _, err := readOptions(context.Background(), request(groundingURL), f, Options{RedirectPolicies: []string{}}); !errors.Is(err, ErrRedirectOrigin) {
		t.Fatal(err)
	}
	if len(log.all()) != 4 || log.to("example.com") != 2 {
		t.Fatal(log.all())
	}
}

// The policy hop is one of the six requests a read may make.
func TestThePolicyHopCountsTowardTheRequestBound(t *testing.T) {
	f, log := hostsFixture(t, map[string]http.HandlerFunc{
		"vertexaisearch.cloud.google.com": redirect("https://example.com/hop"),
		"example.com":                     func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/hop", 302) },
	}, nil)
	if _, err := readOptions(context.Background(), request(groundingURL), f, grounding()); !errors.Is(err, ErrRedirect) || len(log.all()) != 6 {
		t.Fatal(err, len(log.all()))
	}
}

// The refusal line is the token, and the member only when the whole line
// arrives within what the gateway carries of a source's standard error.
func TestTheRefusalLineIsBounded(t *testing.T) {
	long := "https://" + strings.Repeat("a", 60) + "." + strings.Repeat("b", 60) + ".example.org"
	for _, c := range []struct {
		err  error
		want string
	}{
		{ErrRedirectOrigin, "web-redirect-origin"},
		{ErrPrivate, "web-public-only"},
		{&RedirectRefusal{From: "https://example.com", To: long}, "web-redirect-origin"},
		{&RedirectRefusal{From: "https://example.com", To: "https://example.org"}, `web-redirect-origin {"redirect":{"from":"https://example.com","permitted":false,"policy":null,"to":"https://example.org"}}`},
	} {
		if got := RefusalLine(c.err); got != c.want || len(got) > maxRefusalLine {
			t.Errorf("%q, want %q", got, c.want)
		}
	}
}

// The grounding endpoint is exactly one host, path prefix and token segment.
func TestGroundingEndpointShape(t *testing.T) {
	for raw, want := range map[string]bool{
		groundingURL: true,
		"https://vertexaisearch.cloud.google.com:443/grounding-api-redirect/T":  true,
		"http://vertexaisearch.cloud.google.com/grounding-api-redirect/T":       false,
		"https://vertexaisearch.cloud.google.com:8443/grounding-api-redirect/T": false,
		"https://u:p@vertexaisearch.cloud.google.com/grounding-api-redirect/T":  false,
		"https://vertexaisearch.cloud.google.com/grounding-api-redirect/.":      false,
	} {
		u, err := url.Parse(raw)
		if err != nil || attachment.GroundingRedirectEndpoint(u) != want {
			t.Error(raw, want)
		}
	}
}

// A cross-origin destination whose DNS answers are private, or mixed, is
// refused as the dial would refuse it, whether or not the policy is enabled
// and on whichever hop: the bare web-public-only, no member, the destination's
// name nowhere in the line, and no request to it. A refusal never tells a
// consumer that a configuration review would help where it would not.
func TestAPrivateDestinationIsAHardRefusalWithOrWithoutThePolicy(t *testing.T) {
	for _, answers := range [][]string{{"10.0.0.7"}, {"8.8.8.8", "10.0.0.7"}} {
		for _, options := range []Options{{}, grounding()} {
			for _, c := range []struct {
				name, url string
				routes    map[string]http.HandlerFunc
				requests  int
			}{
				{"grounding hop", groundingURL, nil, 1},
				{"after the policy hop", groundingURL, map[string]http.HandlerFunc{"vertexaisearch.cloud.google.com": redirect("https://example.com/report"), "example.com": redirect("https://private.example.com/report")}, 2},
				{"ordinary site", "https://example.com/start", map[string]http.HandlerFunc{"example.com": redirect("https://private.example.com/report")}, 1},
				{"a later hop", "https://example.com/start", map[string]http.HandlerFunc{"example.com": func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/start" {
						http.Redirect(w, r, "/next", 302)
						return
					}
					redirect("https://private.example.com/report")(w, r)
				}}, 2},
			} {
				if c.name == "after the policy hop" && len(options.RedirectPolicies) == 0 {
					continue // without the policy the hop to example.com is refused first
				}
				t.Run(fmt.Sprintf("%s/%v/%v", c.name, answers, options.RedirectPolicies), func(t *testing.T) {
					routes := map[string]http.HandlerFunc{
						"vertexaisearch.cloud.google.com": redirect("https://private.example.com/report"),
						"private.example.com":             func(http.ResponseWriter, *http.Request) { t.Error("the private destination was contacted") },
					}
					for host, route := range c.routes {
						routes[host] = route
					}
					f, log := hostsFixture(t, routes, map[string][]string{"private.example.com": answers})
					_, err := readOptions(context.Background(), request(c.url), f, options)
					var refusal *RedirectRefusal
					if !errors.Is(err, ErrPrivate) || errors.As(err, &refusal) || len(log.all()) != c.requests || log.to("private.example.com") != 0 {
						t.Fatal(err, log.all())
					}
					if line := RefusalLine(err); line != "web-public-only" || strings.Contains(line, "private.example.com") {
						t.Fatal(line)
					}
				})
			}
		}
	}
}
