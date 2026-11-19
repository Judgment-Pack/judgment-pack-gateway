package metadataclient

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// errNotDialed is what the recording dialer answers: no test of this
// package connects through it.
var errNotDialed = errors.New("recorded, not dialed")

// recordDials replaces dial for the rest of the test with one that records
// each address it is asked for and connects nowhere.
func recordDials(t *testing.T) func() []string {
	t.Helper()
	var mu sync.Mutex
	var addresses []string
	previous := dial
	dial = func(_ context.Context, _ *net.Dialer, _, address string) (net.Conn, error) {
		mu.Lock()
		defer mu.Unlock()
		addresses = append(addresses, address)
		return nil, errNotDialed
	}
	t.Cleanup(func() { dial = previous })
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), addresses...)
	}
}

// The metadata server is the platform's link-local address, an IP literal
// over http, and a base that is not one is no client: a name is never
// resolved.
func TestTheAddressIsTheLinkLocalIPLiteral(t *testing.T) {
	if Address != "http://169.254.169.254" {
		t.Fatalf("the metadata server is %q, not the platform's fixed address", Address)
	}
	if _, err := New(Address, time.Second); err != nil {
		t.Fatalf("the fixed address: %v", err)
	}
	for _, base := range []string{"http://metadata.google.internal", "http://localhost:80", "https://169.254.169.254", "http://", "", "169.254.169.254", "http://[::1"} {
		if client, err := New(base, time.Second); client != nil || !errors.Is(err, ErrAddress) {
			t.Errorf("the base %q: %v", base, err)
		}
	}
}

// The client dials the pinned address and port alone. A request for a name,
// for another IP, for another port of the same IP, and for the fixed address
// when the client is pinned elsewhere is refused at dial: the dialer is never
// asked. A request for the fixed address reaches the dialer as that IP and
// port 80, and nothing else does; the recording dialer connects nowhere.
func TestTheClientDialsThePinnedAddressAlone(t *testing.T) {
	dials := recordDials(t)
	client, err := New(Address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"http://metadata.google.internal/computeMetadata/v1/", "http://localhost/computeMetadata/v1/", "http://169.254.169.253/computeMetadata/v1/", "http://169.254.169.254:8080/computeMetadata/v1/", "http://[fd00:ec2::254]/computeMetadata/v1/"} {
		if _, err := client.Get(target); !errors.Is(err, ErrAddress) {
			t.Errorf("a request for %s: %v", target, err)
		}
	}
	if got := dials(); len(got) != 0 {
		t.Fatalf("a request for another address reached the dialer: %v", got)
	}
	if _, err := client.Get(Address + "/computeMetadata/v1/"); !errors.Is(err, errNotDialed) {
		t.Fatalf("a request for the fixed address: %v", err)
	}
	if got := dials(); len(got) != 1 || got[0] != "169.254.169.254:80" {
		t.Fatalf("the fixed address was dialed as %v", got)
	}
	// Pinned to a stand-in's address, the fixed address is another address.
	pinned, err := New("http://127.0.0.1:9", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pinned.Get(Address + "/computeMetadata/v1/"); !errors.Is(err, ErrAddress) {
		t.Fatalf("the fixed address from a client pinned elsewhere: %v", err)
	}
	if got := dials(); len(got) != 1 {
		t.Fatalf("a client pinned elsewhere dialed %v", got[1:])
	}
}

// The client takes no proxy from the environment: its transport has no
// proxy function at all, since Go's environment proxy lets a loopback
// address by and the stand-in's hits alone could not tell. With every proxy
// variable naming a stand-in proxy, the request reaches the stand-in
// metadata server directly and the proxy is asked nothing.
func TestTheClientTakesNoProxyFromTheEnvironment(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("the proxy was asked") }))
	defer proxy.Close()
	for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		t.Setenv(name, proxy.URL)
	}
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
	var hits atomic.Int64
	stand := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Metadata-Flavor", "Google")
	}))
	defer stand.Close()
	client, err := New(stand.URL, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if transport, ok := client.Transport.(*http.Transport); !ok || transport.Proxy != nil {
		t.Fatal("the metadata client's transport takes a proxy")
	}
	resp, err := client.Get(stand.URL + "/computeMetadata/v1/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if hits.Load() != 1 {
		t.Fatalf("the stand-in was asked %d times, not once", hits.Load())
	}
}

// A redirect is not followed, even to the same address: the request is
// ErrRedirect and the stand-in is asked once.
func TestTheClientFollowsNoRedirect(t *testing.T) {
	var hits, redirected atomic.Int64
	stand := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if strings.HasSuffix(r.URL.Path, "/elsewhere") {
			redirected.Add(1)
			return
		}
		w.Header().Set("Metadata-Flavor", "Google")
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	}))
	defer stand.Close()
	client, err := New(stand.URL, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Get(stand.URL + "/computeMetadata/v1/"); !errors.Is(err, ErrRedirect) {
		t.Fatalf("a redirect: %v", err)
	}
	if hits.Load() != 1 || redirected.Load() != 0 {
		t.Fatalf("the redirect was followed: %d requests", hits.Load())
	}
}

// An answer is the metadata server's only with Metadata-Flavor: Google
// exactly once.
func TestFlavoredIsGoogleExactlyOnce(t *testing.T) {
	cases := map[string]struct {
		values []string
		want   bool
	}{
		"once":         {[]string{"Google"}, true},
		"absent":       {nil, false},
		"empty":        {[]string{""}, false},
		"twice":        {[]string{"Google", "Google"}, false},
		"another case": {[]string{"google"}, false},
		"padded":       {[]string{"Google "}, false},
	}
	for name, c := range cases {
		header := http.Header{}
		for _, v := range c.values {
			header.Add("Metadata-Flavor", v)
		}
		if got := Flavored(header); got != c.want {
			t.Errorf("%s: Flavored = %v, want %v", name, got, c.want)
		}
	}
}
