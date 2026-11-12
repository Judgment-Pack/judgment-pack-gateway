package main

// Where serve --config listens (#400, ADR-0025): an engine configuration's
// listen is a loopback address, rewritten to one spelling as it always was,
// unless from engineVersion 19 it names another, written exactly as it is
// bound, beside an identity and acceptOtherHostsOverPlainHTTP: true, and
// with neither a witness nor mcp. Nothing here binds an address other hosts
// can reach: what is bound and written for one is seen through serveListen's
// stand-in, which binds a loopback port of the test's own.

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// listenConfig is a configuration of the version given, its listen
// replaced, with extra members after the catalog and no platform.
func listenConfig(t *testing.T, version, listen, extra string) string {
	t.Helper()
	text := engineJSON(t, t.TempDir(), extra, ``)
	text = strings.Replace(text, `"engineVersion":"1"`, `"engineVersion":"`+version+`"`, 1)
	return strings.Replace(text, `"listen":"127.0.0.1:8787"`, `"listen":"`+listen+`"`, 1)
}

// listenIdentity is an identity member whose key file need not exist: the
// configuration's parse reads no key.
func listenIdentity(t *testing.T) string {
	t.Helper()
	return `,"identity":{"issuer":"https://login.example","audience":"gateway:acme","keys":"` + abs(t, t.TempDir(), "keys.json") + `"}`
}

const acceptOtherHosts = `,"acceptOtherHostsOverPlainHTTP":true`

// The refusal of a listen that is not loopback without both members, in
// these bytes, which name both whichever is missing.
func offLoopbackRefusal(listen, missing string) string {
	return "engine configuration: listen " + listen + " is not a loopback address: other hosts can reach it, so the engine listens there only with identity, " +
		"by which every endpoint but /registry and /publickey holds its caller to a token, and acceptOtherHostsOverPlainHTTP: true, " +
		"which acknowledges that the tokens cross plain HTTP unless TLS terminates in front of the engine; " + missing
}

// A listen that is not loopback loads at version 19 with an identity and
// the acknowledgment, and is held exactly as written.
func TestAConfigurationListensOffLoopbackWithAnIdentityAndTheAcknowledgment(t *testing.T) {
	for _, listen := range []string{"0.0.0.0:8787", "[::]:8787", "192.0.2.10:8787", "[2001:db8::1]:9000", "192.0.2.10:0"} {
		t.Run(listen, func(t *testing.T) {
			cfg, err := parseEngineConfig([]byte(listenConfig(t, "19", listen, listenIdentity(t)+acceptOtherHosts)))
			if err != nil {
				t.Fatal(err)
			}
			if cfg.listen != listen || cfg.identity == nil {
				t.Fatalf("listen %q, identity %v", cfg.listen, cfg.identity)
			}
		})
	}
}

// Every way a configuration can ask for a listen that is not loopback, or
// carry the acknowledgment, that is refused at load, in these exact bytes.
func TestAListenOffLoopbackIsRefusedWithoutBothMembers(t *testing.T) {
	id := listenIdentity(t)
	const notAnAddress = " is not an IP address and a port: IPv4 in dotted decimal, or IPv6 in brackets, with no zone; a name is not one, localhost included"
	written := func(listen, as string) string {
		return `engine configuration: listen "` + listen + `" is the address ` + as + ` written another way; give it as ` + as
	}
	for _, tc := range []struct{ name, text, want string }{
		// both members, and each alone, at version 19
		{"neither", listenConfig(t, "19", "0.0.0.0:8787", ``), offLoopbackRefusal("0.0.0.0:8787", "this configuration has neither")},
		{"the acknowledgment false, no identity", listenConfig(t, "19", "[::]:8787", `,"acceptOtherHostsOverPlainHTTP":false`), offLoopbackRefusal("[::]:8787", "this configuration has neither")},
		{"an identity alone", listenConfig(t, "19", "192.0.2.10:8787", id), offLoopbackRefusal("192.0.2.10:8787", "this configuration does not set acceptOtherHostsOverPlainHTTP to true")},
		{"an identity, the acknowledgment false", listenConfig(t, "19", "192.0.2.10:8787", id+`,"acceptOtherHostsOverPlainHTTP":false`), offLoopbackRefusal("192.0.2.10:8787", "this configuration does not set acceptOtherHostsOverPlainHTTP to true")},
		{"the acknowledgment alone", listenConfig(t, "19", "[2001:db8::1]:8787", acceptOtherHosts), offLoopbackRefusal("[2001:db8::1]:8787", "this configuration has no identity")},
		{"no identity, beside mcp", listenConfig(t, "19", "0.0.0.0:8787", acceptOtherHosts+`,"mcp":{"listen":"127.0.0.1:8788"}`), offLoopbackRefusal("0.0.0.0:8787", "this configuration has no identity")},
		// versions 18 and earlier: refused as before, and the member is not theirs
		{"version 18, both members", listenConfig(t, "18", "0.0.0.0:8787", id+acceptOtherHosts), "engine configuration: acceptOtherHostsOverPlainHTTP is a version-19 member; engineVersion 18 has no acceptOtherHostsOverPlainHTTP"},
		{"version 18, an identity", listenConfig(t, "18", "0.0.0.0:8787", id), `engine configuration: listen "0.0.0.0:8787" is not a literal loopback address; the engine listens on 127.0.0.1 or ::1 only`},
		{"version 1, an identity", listenConfig(t, "1", "192.0.2.10:8787", id), `engine configuration: listen "192.0.2.10:8787" is not a literal loopback address; the engine listens on 127.0.0.1 or ::1 only`},
		{"version 18, the acknowledgment on loopback", listenConfig(t, "18", "127.0.0.1:8787", id+acceptOtherHosts), "engine configuration: acceptOtherHostsOverPlainHTTP is a version-19 member; engineVersion 18 has no acceptOtherHostsOverPlainHTTP"},
		{"version 1, the acknowledgment false", listenConfig(t, "1", "127.0.0.1:8787", `,"acceptOtherHostsOverPlainHTTP":false`), "engine configuration: acceptOtherHostsOverPlainHTTP is a version-19 member; engineVersion 1 has no acceptOtherHostsOverPlainHTTP"},
		// the acknowledgment beside loopback, as the listen is held
		{"the acknowledgment beside 127.0.0.1", listenConfig(t, "19", "127.0.0.1:8787", id+acceptOtherHosts), "engine configuration: acceptOtherHostsOverPlainHTTP is true, and listen 127.0.0.1:8787 is a loopback address: the member acknowledges a listen that is not loopback, and is true only beside one"},
		{"the acknowledgment beside ::1", listenConfig(t, "19", "[::1]:8787", acceptOtherHosts), "engine configuration: acceptOtherHostsOverPlainHTTP is true, and listen [::1]:8787 is a loopback address: the member acknowledges a listen that is not loopback, and is true only beside one"},
		{"the acknowledgment beside loopback written another way", listenConfig(t, "19", "[::ffff:127.0.0.2]:08787", id+acceptOtherHosts), "engine configuration: acceptOtherHostsOverPlainHTTP is true, and listen 127.0.0.2:8787 is a loopback address: the member acknowledges a listen that is not loopback, and is true only beside one"},
		// the member is true or false
		{"the acknowledgment a string", listenConfig(t, "19", "0.0.0.0:8787", id+`,"acceptOtherHostsOverPlainHTTP":"true"`), "engine configuration: acceptOtherHostsOverPlainHTTP, when present, is true or false"},
		{"the acknowledgment a number", listenConfig(t, "19", "0.0.0.0:8787", id+`,"acceptOtherHostsOverPlainHTTP":1`), "engine configuration: acceptOtherHostsOverPlainHTTP, when present, is true or false"},
		{"the acknowledgment null", listenConfig(t, "19", "0.0.0.0:8787", id+`,"acceptOtherHostsOverPlainHTTP":null`), "engine configuration: acceptOtherHostsOverPlainHTTP, when present, is true or false"},
		{"the acknowledgment twice", listenConfig(t, "19", "0.0.0.0:8787", id+acceptOtherHosts+acceptOtherHosts), `engine configuration: duplicate member name "acceptOtherHostsOverPlainHTTP"`},
		// the address: an IP literal, no name, no zone, written as it is bound
		{"localhost", listenConfig(t, "19", "localhost:8787", id+acceptOtherHosts), `engine configuration: listen "localhost:8787"` + notAnAddress},
		{"a host name", listenConfig(t, "19", "gateway.internal:8787", id+acceptOtherHosts), `engine configuration: listen "gateway.internal:8787"` + notAnAddress},
		{"an empty host, which would bind both families", listenConfig(t, "19", ":8787", id+acceptOtherHosts), `engine configuration: listen ":8787"` + notAnAddress},
		{"a star", listenConfig(t, "19", "*:8787", id+acceptOtherHosts), `engine configuration: listen "*:8787"` + notAnAddress},
		{"a zone", listenConfig(t, "19", "[fe80::1%eth0]:8787", id+acceptOtherHosts), `engine configuration: listen "[fe80::1%eth0]:8787"` + notAnAddress},
		{"a zone on loopback", listenConfig(t, "19", "[::1%lo]:8787", id+acceptOtherHosts), `engine configuration: listen "[::1%lo]:8787"` + notAnAddress},
		{"a leading zero in the address", listenConfig(t, "19", "192.0.2.010:8787", id+acceptOtherHosts), `engine configuration: listen "192.0.2.010:8787"` + notAnAddress},
		{"no port", listenConfig(t, "19", "192.0.2.10", id+acceptOtherHosts), `engine configuration: listen "192.0.2.10" is not host:port`},
		{"IPv6 without brackets", listenConfig(t, "19", "2001:db8::1", id+acceptOtherHosts), `engine configuration: listen "2001:db8::1" is not host:port`},
		{"an empty port", listenConfig(t, "19", "192.0.2.10:", id+acceptOtherHosts), `engine configuration: listen "192.0.2.10:" has no valid port`},
		{"a port by name", listenConfig(t, "19", "192.0.2.10:http", id+acceptOtherHosts), `engine configuration: listen "192.0.2.10:http" has no valid port`},
		{"a port out of range", listenConfig(t, "19", "192.0.2.10:65536", id+acceptOtherHosts), `engine configuration: listen "192.0.2.10:65536" has no valid port`},
		{"a negative port", listenConfig(t, "19", "192.0.2.10:-1", id+acceptOtherHosts), `engine configuration: listen "192.0.2.10:-1" has no valid port`},
		{"a port with a leading zero", listenConfig(t, "19", "192.0.2.10:08787", id+acceptOtherHosts), written("192.0.2.10:08787", "192.0.2.10:8787")},
		{"a port with a sign", listenConfig(t, "19", "192.0.2.10:+8787", id+acceptOtherHosts), written("192.0.2.10:+8787", "192.0.2.10:8787")},
		{"IPv4 in brackets", listenConfig(t, "19", "[192.0.2.10]:8787", id+acceptOtherHosts), written("[192.0.2.10]:8787", "192.0.2.10:8787")},
		{"IPv4 in IPv6 form", listenConfig(t, "19", "[::ffff:192.0.2.10]:8787", id+acceptOtherHosts), written("[::ffff:192.0.2.10]:8787", "192.0.2.10:8787")},
		{"every IPv6 address, uncompressed", listenConfig(t, "19", "[0:0::0]:8787", id+acceptOtherHosts), written("[0:0::0]:8787", "[::]:8787")},
		{"IPv6 in upper case", listenConfig(t, "19", "[2001:DB8::1]:8787", id+acceptOtherHosts), written("[2001:DB8::1]:8787", "[2001:db8::1]:8787")},
		// mcp, which reaches the signer at listen, beside an address that is not loopback
		{"mcp beside every IPv4 address", listenConfig(t, "19", "0.0.0.0:8787", id+acceptOtherHosts+`,"mcp":{"listen":"127.0.0.1:8788"}`), "engine configuration: mcp beside listen 0.0.0.0:8787, which is not a loopback address: the MCP server reaches the signer at listen, and fronts a signer that listens on a loopback address"},
		{"mcp beside one address of the host's", listenConfig(t, "19", "192.0.2.10:8787", id+acceptOtherHosts+`,"mcp":{"listen":"127.0.0.1:8788"}`), "engine configuration: mcp beside listen 192.0.2.10:8787, which is not a loopback address: the MCP server reaches the signer at listen, and fronts a signer that listens on a loopback address"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseEngineConfig([]byte(tc.text))
			if err == nil || err.Error() != tc.want {
				t.Fatalf("got\n%v\nwant\n%s", err, tc.want)
			}
		})
	}
}

// A witness's signer listens on a loopback address: a witness beside a
// listen that is not loopback is refused at load, identity and
// acknowledgment given, and loads beside a loopback one at version 19.
func TestAWitnessIsRefusedBesideAListenOffLoopback(t *testing.T) {
	base := t.TempDir()
	at := func(listen, extra string) string {
		text := witnessConfigJSON(t, base, witnessMember(t, base, ""))
		text = strings.Replace(text, `"engineVersion":"6"`, `"engineVersion":"19"`, 1)
		return strings.Replace(text, `"listen":"127.0.0.1:8787",`, `"listen":"`+listen+`",`+extra, 1)
	}
	if cfg, err := parseEngineConfig([]byte(at("127.0.0.1:8787", ``))); err != nil || cfg.witness == nil || cfg.listen != "127.0.0.1:8787" {
		t.Fatalf("a witness on loopback at version 19: %v", err)
	}
	for listen, want := range map[string]string{
		"0.0.0.0:8787":    "engine configuration: witness beside listen 0.0.0.0:8787, which is not a loopback address: a witness's two reads are open to anyone, and its signer listens on a loopback address, behind a front that passes other parties the submission, the two reads and /publickey alone",
		"[::]:8787":       "engine configuration: witness beside listen [::]:8787, which is not a loopback address: a witness's two reads are open to anyone, and its signer listens on a loopback address, behind a front that passes other parties the submission, the two reads and /publickey alone",
		"192.0.2.10:8787": "engine configuration: witness beside listen 192.0.2.10:8787, which is not a loopback address: a witness's two reads are open to anyone, and its signer listens on a loopback address, behind a front that passes other parties the submission, the two reads and /publickey alone",
	} {
		if _, err := parseEngineConfig([]byte(at(listen, `"acceptOtherHostsOverPlainHTTP":true,`))); err == nil || err.Error() != want {
			t.Fatalf("%s: got\n%v\nwant\n%s", listen, err, want)
		}
	}
}

// Every loopback listen loads as it did before the member, at every
// version, with or without an identity, and is rewritten to the one
// spelling it was rewritten to before; mcp beside one loads at version 19.
func TestALoopbackListenLoadsAsBefore(t *testing.T) {
	for listen, held := range map[string]string{
		"127.0.0.1:8787": "127.0.0.1:8787", "[::1]:8787": "[::1]:8787", "127.0.0.2:9000": "127.0.0.2:9000",
		"[::ffff:127.0.0.1]:8787": "127.0.0.1:8787", "127.0.0.1:08787": "127.0.0.1:8787", "127.0.0.1:0": "127.0.0.1:0",
	} {
		for _, version := range []string{"1", "18", "19"} {
			for _, extra := range []string{``, listenIdentity(t)} {
				cfg, err := parseEngineConfig([]byte(listenConfig(t, version, listen, extra)))
				if err != nil || cfg.listen != held {
					t.Fatalf("version %s, %q, identity %v: %q %v", version, listen, extra != ``, cfg.listen, err)
				}
			}
		}
		if listen == "127.0.0.1:0" {
			continue // mcp needs the signer's port
		}
		cfg, err := parseEngineConfig([]byte(listenConfig(t, "19", listen, `,"acceptOtherHostsOverPlainHTTP":false,"mcp":{"listen":"127.0.0.1:8788"}`)))
		if err != nil || cfg.listen != held || cfg.mcp == nil {
			t.Fatalf("version 19, %q beside mcp, the acknowledgment false: %v", listen, err)
		}
	}
}

// What serve --config binds for each listen the configuration holds: a
// loopback address as before, "tcp" and nothing written; one that is not
// loopback in its own family, and a line on stderr in these exact bytes,
// before anything else, decided by the address bound.
func TestServeConfigBindsInTheAddresssFamilyAndSaysSo(t *testing.T) {
	const note = ", which is not a loopback address: other hosts can reach this gateway; it holds every caller but those of /registry and /publickey to a token, " +
		"and speaks plain HTTP, so unless TLS terminates in front of it a token can be read and replayed on the network between\n"
	for _, tc := range []struct {
		listen, network string
		bound           *net.TCPAddr
		want            string
	}{
		{"127.0.0.1:8787", "tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8787}, ""},
		{"[::1]:8787", "tcp", &net.TCPAddr{IP: net.IPv6loopback, Port: 8787}, ""},
		{"127.0.0.2:9000", "tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.2"), Port: 9000}, ""},
		{"0.0.0.0:8787", "tcp4", &net.TCPAddr{IP: net.IPv4zero, Port: 8787}, "start: listening on 0.0.0.0:8787" + note},
		{"[::]:9000", "tcp6", &net.TCPAddr{IP: net.IPv6unspecified, Port: 9000}, "start: listening on [::]:9000" + note},
		{"192.0.2.10:8787", "tcp4", &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 8787}, "start: listening on 192.0.2.10:8787" + note},
		{"[2001:db8::1]:8787", "tcp6", &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 8787}, "start: listening on [2001:db8::1]:8787" + note},
	} {
		t.Run(tc.listen, func(t *testing.T) {
			var gotNetwork, gotAddress string
			serveListen = func(network, address string) (net.Listener, error) {
				gotNetwork, gotAddress = network, address
				return standIn{tc.bound}, nil
			}
			t.Cleanup(func() { serveListen = net.Listen })
			var stderr bytes.Buffer
			if _, err := listenForConfig(tc.listen, &stderr); err != nil {
				t.Fatal(err)
			}
			if gotNetwork != tc.network || gotAddress != tc.listen {
				t.Fatalf("bound %q %q, want %q %q", gotNetwork, gotAddress, tc.network, tc.listen)
			}
			if stderr.String() != tc.want {
				t.Fatalf("stderr\n%q, want\n%q", stderr.String(), tc.want)
			}
		})
	}
	// A listen the configuration never holds is refused, never bound in
	// both families.
	serveListen = func(network, address string) (net.Listener, error) {
		t.Fatalf("bound %q %q", network, address)
		return nil, nil
	}
	t.Cleanup(func() { serveListen = net.Listen })
	if _, err := listenForConfig("localhost:8787", io.Discard); err == nil || err.Error() != `listen "localhost:8787" is not an IP address and a port` {
		t.Fatalf("a name: %v", err)
	}
}

// A start of serve --config from a version-19 configuration that listens
// off loopback: the line on stderr comes before the readiness line, every
// endpoint but /registry and /publickey refuses a request without a token,
// and /posture, with one, reports the listener partial. serveListen stands
// in for the bind and binds a loopback port of the test's own, which says
// it holds the configured address; it is a package variable, so this test
// does not run in parallel, and it is put back.
func TestServeConfigOffLoopbackHoldsCallersToATokenAndSaysSo(t *testing.T) {
	issuer := newIssuer(t)
	dir := t.TempDir()
	keys := filepath.Join(dir, "keys.json")
	if err := os.WriteFile(keys, issuer.keySet(), 0o600); err != nil {
		t.Fatal(err)
	}
	identity := `,"identity":{"issuer":"https://login.example","audience":"gateway:acme","keys":"` + abs(t, keys) + `"}`
	cfg, err := parseEngineConfig([]byte(listenConfig(t, "19", "192.0.2.10:8787", identity+acceptOtherHosts)))
	if err != nil {
		t.Fatal(err)
	}
	id, err := loadIdentity(cfg.identity)
	if err != nil {
		t.Fatal(err)
	}
	service, err := buildService(cfg.store, testSeed, cfg.authority, cfg.registry, engineServeOptions(cfg, map[string]sourceSpec{}, id))
	if err != nil {
		t.Fatal(err)
	}
	claim := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 8787}
	bound := make(chan net.Listener, 1)
	var network, address string
	serveListen = func(n, a string) (net.Listener, error) {
		network, address = n, a
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		bound <- l
		return claimed{l, claim}, nil
	}
	t.Cleanup(func() { serveListen = net.Listen })
	stderr := captureStderr(t)
	ctx, cancel := context.WithCancel(context.Background())
	service.bindLifetime(ctx)
	served := make(chan error, 1)
	go func() { served <- service.listenAndServe(cfg.listen) }()
	var listener net.Listener
	select {
	case listener = <-bound:
	case err := <-served:
		t.Fatalf("listenAndServe: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("serve --config bound nothing")
	}
	defer func() {
		cancel()
		if err := <-served; err != nil {
			t.Errorf("listenAndServe: %v", err)
		}
	}()
	if network != "tcp4" || address != "192.0.2.10:8787" {
		t.Fatalf("bound %q %q", network, address)
	}
	ask := func(method, path, authorization string) (int, []byte) {
		t.Helper()
		var body io.Reader
		if method == http.MethodPost {
			body = strings.NewReader(`{}`)
		}
		req, err := http.NewRequest(method, "http://"+listener.Addr().String()+path, body)
		if err != nil {
			t.Fatal(err)
		}
		if authorization != "" {
			req.Header.Set("Authorization", authorization)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		answer, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, answer
	}
	for _, route := range []struct{ method, path string }{
		{http.MethodPost, "/acquire"}, {http.MethodPost, "/act"}, {http.MethodPost, "/seal"},
		{http.MethodGet, "/verify"}, {http.MethodGet, "/posture"},
	} {
		if code, answer := ask(route.method, route.path, ""); code != http.StatusUnauthorized {
			t.Fatalf("%s %s without a token: %d %s", route.method, route.path, code, answer)
		}
	}
	for _, path := range []string{"/registry", "/publickey"} {
		if code, answer := ask(http.MethodGet, path, ""); code != http.StatusOK {
			t.Fatalf("GET %s without a token: %d %s", path, code, answer)
		}
	}
	code, body := ask(http.MethodGet, "/posture", "Bearer "+issuer.mint(t, "ec-1", nil, goodClaims(time.Now())))
	if code != http.StatusOK {
		t.Fatalf("/posture with a token: %d %s", code, body)
	}
	if state, reason := postureLineIn(t, body, protectionListenerReach); state != posturePartial || reason != listenerReachLine(false, true).reason {
		t.Fatalf("the listener of serve --config off loopback: %s", body)
	}
	if bytes.Contains(body, []byte("192.0.2.10")) || bytes.Contains(body, []byte("8787")) {
		t.Fatalf("/posture names the address it listens on: %s", body)
	}
	written := stderr()
	note := otherHostsConfigNote(claim) + "\n"
	if !strings.HasPrefix(written, note+"gateway on http://192.0.2.10:8787 (authority gateway:acme, key ") || strings.Count(written, "start: listening on") != 1 {
		t.Fatalf("stderr\n%q", written)
	}
}

// gateway posture --config judges a version-19 configuration that listens
// off loopback with an identity: partial, as /posture says it as it runs.
func TestPostureOfAConfigurationOffLoopback(t *testing.T) {
	catalog := catalogWith(t, map[string]string{"postgres": postgresBinding})
	text := engineJSON(t, catalog, listenIdentity(t)+acceptOtherHosts, platformJSON(t, "warehouse", "postgres@"+digestOf(postgresBinding), "engine-warehouse", ""))
	text = strings.Replace(text, `"engineVersion":"1"`, `"engineVersion":"19"`, 1)
	text = strings.Replace(text, `"listen":"127.0.0.1:8787"`, `"listen":"[::]:8787"`, 1)
	path := filepath.Join(t.TempDir(), "engine.json")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	in, err := postureOfConfig(path, stubAccounts(stubUsers))
	if err != nil {
		t.Fatal(err)
	}
	want := postureLine{protectionListenerReach, posturePartial, "the gateway listens on an address that is not loopback, which other hosts can reach, and it authenticates its callers by a bearer token, which over plain HTTP can be read and replayed on the network between"}
	if in.listener != (listenerReach{loopback: false, authenticated: true}) || listenerPosture(in) != want {
		t.Fatalf("the configuration's listener: %+v %+v", in.listener, listenerPosture(in))
	}
}
