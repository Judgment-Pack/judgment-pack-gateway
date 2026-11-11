package main

// Where `gateway serve` from the command line listens (#387): 127.0.0.1
// unless --listen names another address, an address held to an IP address
// written as one, one other hosts can reach only with
// --accept-unauthenticated-callers beside it, and a line on stderr when
// what is bound is not loopback. Nothing here binds an address other hosts
// can reach: what is written for one is seen through a stand-in listener.

import (
	"bytes"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// serveArgs is serve's command line with the four positional arguments and
// extra after them.
func serveArgs(extra ...string) []string {
	return append([]string{"store", "seed", "authority", "registry"}, extra...)
}

// Every value --listen refuses, refused as usage with these exact bytes,
// and every pair of options the acknowledgment is held to.
func TestListenIsAnAddressWrittenAsOne(t *testing.T) {
	const notAnAddress = " is not an IP address alone: IPv4 in dotted decimal, or IPv6 bare or in brackets, with no zone and no port; a name is not one, localhost included"
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"no value", serveArgs("--listen"), "--listen requires a following value"},
		{"twice", serveArgs("--listen", "127.0.0.1", "--listen", "127.0.0.2"), "duplicate --listen option"},
		{"empty, which would bind every address", serveArgs("--listen", ""), "--listen must not be empty"},
		{"an IPv4 address with a port", serveArgs("--listen", "127.0.0.1:8787"), `--listen "127.0.0.1:8787" names a port; --listen takes the address alone, and --port the port`},
		{"an IPv6 address with a port", serveArgs("--listen", "[::1]:8787"), `--listen "[::1]:8787" names a port; --listen takes the address alone, and --port the port`},
		{"a name", serveArgs("--listen", "localhost"), `--listen "localhost"` + notAnAddress},
		{"a name with a port", serveArgs("--listen", "localhost:8787"), `--listen "localhost:8787"` + notAnAddress},
		{"a wildcard that is not an address", serveArgs("--listen", "*"), `--listen "*"` + notAnAddress},
		{"a number that is not an address", serveArgs("--listen", "0"), `--listen "0"` + notAnAddress},
		{"surrounding space", serveArgs("--listen", " 127.0.0.1"), `--listen " 127.0.0.1"` + notAnAddress},
		{"a leading zero", serveArgs("--listen", "127.0.0.01"), `--listen "127.0.0.01"` + notAnAddress},
		{"a zone", serveArgs("--listen", "fe80::1%eth0"), `--listen "fe80::1%eth0"` + notAnAddress},
		{"an open bracket", serveArgs("--listen", "[::1"), `--listen "[::1"` + notAnAddress},
		{"a close bracket", serveArgs("--listen", "::1]"), `--listen "::1]"` + notAnAddress},
		{"empty brackets", serveArgs("--listen", "[]"), `--listen "[]"` + notAnAddress},
		{"an option where the value goes", serveArgs("--listen", "--port", "8787"), `--listen "--port"` + notAnAddress},
		{"an IPv4 address in brackets", serveArgs("--listen", "[127.0.0.1]"), `--listen "[127.0.0.1]" is the address 127.0.0.1 written another way; give it as 127.0.0.1`},
		{"an IPv4 address in IPv6 form", serveArgs("--listen", "::ffff:127.0.0.1"), `--listen "::ffff:127.0.0.1" is the address 127.0.0.1 written another way; give it as 127.0.0.1`},
		{"every IPv6 address, uncompressed", serveArgs("--listen", "0:0::0"), `--listen "0:0::0" is the address :: written another way; give it as ::`},
		{"IPv6 in upper case", serveArgs("--listen", "FE80::1"), `--listen "FE80::1" is the address fe80::1 written another way; give it as fe80::1`},
		{"every IPv4 address, unacknowledged", serveArgs("--listen", "0.0.0.0"), "--listen 0.0.0.0 is not a loopback address: other hosts can reach it, and serve from the command line authenticates no caller; give --accept-unauthenticated-callers as well to listen there"},
		{"every IPv6 address, unacknowledged", serveArgs("--listen", "[::]"), "--listen :: is not a loopback address: other hosts can reach it, and serve from the command line authenticates no caller; give --accept-unauthenticated-callers as well to listen there"},
		{"one address of the host's, unacknowledged", serveArgs("--port", "9000", "--listen", "192.0.2.10"), "--listen 192.0.2.10 is not a loopback address: other hosts can reach it, and serve from the command line authenticates no caller; give --accept-unauthenticated-callers as well to listen there"},
		{"the acknowledgment alone", serveArgs("--accept-unauthenticated-callers"), "--accept-unauthenticated-callers is given without a --listen address that is not loopback"},
		{"the acknowledgment beside loopback", serveArgs("--accept-unauthenticated-callers", "--listen", "::1"), "--accept-unauthenticated-callers is given without a --listen address that is not loopback"},
		{"the acknowledgment twice", serveArgs("--listen", "0.0.0.0", "--accept-unauthenticated-callers", "--accept-unauthenticated-callers"), "duplicate --accept-unauthenticated-callers option"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, msg, ok := parseServeOptions(tc.args)
			if ok {
				t.Fatalf("parseServeOptions(%q) accepted it", tc.args)
			}
			if msg != tc.want {
				t.Fatalf("parseServeOptions(%q) refused it with\n%q, want\n%q", tc.args, msg, tc.want)
			}
		})
	}
}

// What serve binds for each command line it takes: with no --listen,
// 127.0.0.1 at --port as before; with one, the address in its own family.
func TestListenBindsTheAddressInItsOwnFamily(t *testing.T) {
	for _, tc := range []struct {
		name             string
		args             []string
		network, address string
	}{
		{"no --listen", serveArgs(), "tcp", "127.0.0.1:8787"},
		{"no --listen, a port", serveArgs("--port", "9000"), "tcp", "127.0.0.1:9000"},
		{"127.0.0.1 written out", serveArgs("--listen", "127.0.0.1"), "tcp4", "127.0.0.1:8787"},
		{"another loopback address", serveArgs("--listen", "127.0.0.2", "--port", "9000"), "tcp4", "127.0.0.2:9000"},
		{"IPv6 loopback", serveArgs("--listen", "::1"), "tcp6", "[::1]:8787"},
		{"IPv6 loopback in brackets", serveArgs("--listen", "[::1]"), "tcp6", "[::1]:8787"},
		{"every IPv4 address", serveArgs("--listen", "0.0.0.0", "--accept-unauthenticated-callers"), "tcp4", "0.0.0.0:8787"},
		{"every IPv6 address", serveArgs("--accept-unauthenticated-callers", "--listen", "::"), "tcp6", "[::]:8787"},
		{"one address of the host's", serveArgs("--listen", "192.0.2.10", "--accept-unauthenticated-callers", "--port", "9000"), "tcp4", "192.0.2.10:9000"},
		{"one IPv6 address of the host's", serveArgs("--listen", "2001:db8::1", "--accept-unauthenticated-callers"), "tcp6", "[2001:db8::1]:8787"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts, msg, ok := parseServeOptions(tc.args)
			if !ok {
				t.Fatalf("parseServeOptions(%q): %s", tc.args, msg)
			}
			network, address := opts.listenAt()
			if network != tc.network || address != tc.address {
				t.Fatalf("listenAt() = %q %q, want %q %q", network, address, tc.network, tc.address)
			}
		})
	}
}

// boundOn binds a free port at host where the platform has host, and
// returns the port, or skips: 127.0.0.2 is not configured on every
// platform, and ::1 is absent where IPv6 is off.
func boundOn(t *testing.T, network, host string) string {
	t.Helper()
	l, err := net.Listen(network, net.JoinHostPort(host, "0"))
	if err != nil {
		t.Skipf("%s is not an address this host can bind: %v", host, err)
	}
	defer l.Close()
	return strconv.Itoa(l.Addr().(*net.TCPAddr).Port)
}

// listened binds what the command line says through listenForServe, and
// gives the address bound and what was written on stderr.
func listened(t *testing.T, args []string) (*net.TCPAddr, string) {
	t.Helper()
	opts, msg, ok := parseServeOptions(args)
	if !ok {
		t.Fatalf("parseServeOptions(%q): %s", args, msg)
	}
	var stderr bytes.Buffer
	listener, err := listenForServe(opts, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr), stderr.String()
}

// The default binds 127.0.0.1 and nothing else, judged by the address the
// listener holds, and writes nothing.
func TestServeListensOnLoopbackOnlyByDefault(t *testing.T) {
	port := boundOn(t, "tcp4", "127.0.0.1")
	addr, stderr := listened(t, serveArgs("--port", port))
	if addr.String() != "127.0.0.1:"+port || !addr.IP.IsLoopback() {
		t.Fatalf("bound %s, want 127.0.0.1:%s", addr, port)
	}
	if stderr != "" {
		t.Fatalf("a loopback listener wrote %q", stderr)
	}
}

// --listen binds the address it names, and a loopback address writes
// nothing.
func TestServeListensWhereListenSays(t *testing.T) {
	for _, tc := range []struct{ network, host, bound string }{
		{"tcp4", "127.0.0.2", "127.0.0.2"},
		{"tcp6", "::1", "[::1]"},
	} {
		t.Run(tc.host, func(t *testing.T) {
			port := boundOn(t, tc.network, tc.host)
			addr, stderr := listened(t, serveArgs("--listen", tc.host, "--port", port))
			if addr.String() != tc.bound+":"+port {
				t.Fatalf("bound %s, want %s:%s", addr, tc.bound, port)
			}
			if stderr != "" {
				t.Fatalf("a loopback listener wrote %q", stderr)
			}
		})
	}
}

// standIn is a listener bound to nothing, which says it holds addr.
type standIn struct{ addr net.Addr }

func (s standIn) Accept() (net.Conn, error) { return nil, errors.New("a stand-in accepts nothing") }
func (s standIn) Close() error              { return nil }
func (s standIn) Addr() net.Addr            { return s.addr }

// An address other hosts can reach is named on stderr, in these exact
// bytes, and the line is decided by the address bound: a stand-in takes
// the place of the listener so that the test binds nothing.
func TestServeSaysWhenOtherHostsCanReachIt(t *testing.T) {
	const note = ", which is not a loopback address: other hosts can reach this gateway, and it authenticates no caller, " +
		"so whoever reaches it can run its sources and have receipts and seals signed under its key\n"
	for _, tc := range []struct {
		name             string
		args             []string
		network, address string
		bound            *net.TCPAddr
		want             string
	}{
		{"every IPv4 address", serveArgs("--listen", "0.0.0.0", "--accept-unauthenticated-callers"), "tcp4", "0.0.0.0:8787",
			&net.TCPAddr{IP: net.IPv4zero, Port: 8787}, "start: listening on 0.0.0.0:8787" + note},
		{"every IPv6 address", serveArgs("--listen", "::", "--accept-unauthenticated-callers", "--port", "9000"), "tcp6", "[::]:9000",
			&net.TCPAddr{IP: net.IPv6unspecified, Port: 9000}, "start: listening on [::]:9000" + note},
		{"one address of the host's", serveArgs("--listen", "192.0.2.10", "--accept-unauthenticated-callers"), "tcp4", "192.0.2.10:8787",
			&net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 8787}, "start: listening on 192.0.2.10:8787" + note},
		{"a loopback address", serveArgs("--listen", "127.0.0.2"), "tcp4", "127.0.0.2:8787",
			&net.TCPAddr{IP: net.ParseIP("127.0.0.2"), Port: 8787}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts, msg, ok := parseServeOptions(tc.args)
			if !ok {
				t.Fatalf("parseServeOptions(%q): %s", tc.args, msg)
			}
			var gotNetwork, gotAddress string
			serveListen = func(network, address string) (net.Listener, error) {
				gotNetwork, gotAddress = network, address
				return standIn{tc.bound}, nil
			}
			t.Cleanup(func() { serveListen = net.Listen })
			var stderr bytes.Buffer
			if _, err := listenForServe(opts, &stderr); err != nil {
				t.Fatal(err)
			}
			if gotNetwork != tc.network || gotAddress != tc.address {
				t.Fatalf("bound %q %q, want %q %q", gotNetwork, gotAddress, tc.network, tc.address)
			}
			if stderr.String() != tc.want {
				t.Fatalf("stderr\n%q, want\n%q", stderr.String(), tc.want)
			}
		})
	}
}

// A refused --listen is a usage error before anything is read or made:
// exit 2, the message alone on stderr, and no store.
func TestServeRefusesAnUnacknowledgedListenBeforeAnythingIsMade(t *testing.T) {
	dir := t.TempDir()
	store := filepath.Join(dir, "store")
	stderr := captureStderr(t)
	code := cmdServe([]string{store, filepath.Join(dir, "absent.seed"), "gateway:test", filepath.Join(dir, "registry.jsonl"), "--listen", "0.0.0.0"})
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	const want = "--listen 0.0.0.0 is not a loopback address: other hosts can reach it, and serve from the command line authenticates no caller; give --accept-unauthenticated-callers as well to listen there\n"
	if got := stderr(); got != want {
		t.Fatalf("stderr\n%q, want\n%q", got, want)
	}
	for _, path := range []string{store, filepath.Join(dir, "registry.jsonl")} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s was made, or cannot be read: %v", filepath.Base(path), err)
		}
	}
}
