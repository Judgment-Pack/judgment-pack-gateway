package main

// Where `gateway serve` listens. From the command line (#387): 127.0.0.1 at
// --port, as it always has, or the address --listen names. That form of
// serve has no identity, so it authenticates no caller: whoever reaches the
// listener can run its sources and have receipts and seals signed under its
// key. An address other hosts can reach is therefore taken only with
// --accept-unauthenticated-callers beside it, and the start says on stderr
// that it listens there. `serve --config` listens on its configuration's
// `listen` (#400): a loopback address (engine.go, loopbackAddress), or,
// from engineVersion 19, an address that is not loopback, held to the rule
// --listen is held to (listenIP) and taken only beside an identity and
// acceptOtherHostsOverPlainHTTP (engine.go, engineListen); its start says
// on stderr that it listens there too, in a sentence of its own, since that
// form authenticates its callers.

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// parseListenAddress holds --listen's value to an IP address alone,
// written in the one form the readiness line prints it in: IPv4 in dotted
// decimal, or IPv6 compressed and in lowercase, bare or in brackets. A name
// is refused, localhost included, since a resolver decides what it binds
// and may map it elsewhere; so are a zone, a port (the port is --port's),
// and an empty value, so that every address of a family, 0.0.0.0 or ::, is
// bound only when it is written out.
func parseListenAddress(value string) (netip.Addr, string, bool) {
	if value == "" {
		return netip.Addr{}, "--listen must not be empty", false
	}
	if _, err := netip.ParseAddrPort(value); err == nil {
		return netip.Addr{}, fmt.Sprintf("--listen %q names a port; --listen takes the address alone, and --port the port", value), false
	}
	written := value
	bracketed := strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]")
	if bracketed {
		written = value[1 : len(value)-1]
	}
	canonical, asWritten, ok := listenIP(written)
	if !ok {
		return netip.Addr{}, fmt.Sprintf("--listen %q is not an IP address alone: IPv4 in dotted decimal, or IPv6 bare or in brackets, with no zone and no port; a name is not one, localhost included", value), false
	}
	// brackets are IPv6's
	if !asWritten || (bracketed && !canonical.Is6()) {
		return netip.Addr{}, fmt.Sprintf("--listen %q is the address %s written another way; give it as %s", value, canonical, canonical), false
	}
	return canonical, "", true
}

// listenIP is the one rule both forms of serve hold an address to that
// they may bind off loopback: --listen (parseListenAddress) and an engine
// configuration's listen (otherHostsListen). written must be an IP address
// alone, with no zone: a name is none, localhost included, so no resolver
// decides what is bound. It gives the address in the one form the
// readiness line prints it in -- IPv4 in dotted decimal, an IPv4 address in
// IPv6 form as the IPv4 address, IPv6 compressed and in lowercase -- and
// whether written is that form already.
func listenIP(written string) (canonical netip.Addr, asWritten, ok bool) {
	addr, err := netip.ParseAddr(written)
	if err != nil || addr.Zone() != "" {
		return netip.Addr{}, false, false
	}
	canonical = addr.Unmap()
	return canonical, canonical.String() == written, true
}

// otherHostsListen holds an engine configuration's listen that is not a
// loopback address (engineVersion 19, #400) to host:port, the host an IP
// address under listenIP's rule, and the whole written exactly as it is
// bound and printed: IPv4 bare, IPv6 in brackets, compressed and in
// lowercase, the port a number with no sign and no leading zero. Every
// address of a family, 0.0.0.0 or [::], is taken only when written out,
// and an empty host, which would bind both families, is no address. A
// loopback listen keeps loopbackAddress's rule, which takes other
// spellings and rewrites them, as it always has.
func otherHostsListen(listen string) (netip.AddrPort, error) {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("listen %q is not host:port", listen)
	}
	addr, _, ok := listenIP(host)
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("listen %q is not an IP address and a port: IPv4 in dotted decimal, or IPv6 in brackets, with no zone; a name is not one, localhost included", listen)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 0 || n > 65535 {
		return netip.AddrPort{}, fmt.Errorf("listen %q has no valid port", listen)
	}
	canonical := netip.AddrPortFrom(addr, uint16(n))
	if canonical.String() != listen {
		return netip.AddrPort{}, fmt.Errorf("listen %q is the address %s written another way; give it as %s", listen, canonical, canonical)
	}
	return canonical, nil
}

// listenNetwork is the network an address is bound in: its own family, so
// that 0.0.0.0 binds every IPv4 address and no IPv6 one, and :: every IPv6
// address and no IPv4 one; "tcp" would bind both for either.
func listenNetwork(addr netip.Addr) string {
	if addr.Is6() {
		return "tcp6"
	}
	return "tcp4"
}

// listenAt is the network and the address serve from the command line
// binds. With no --listen it is 127.0.0.1 at --port, with the network it
// has always been bound with. With one it is the address named, in that
// address's own family (listenNetwork).
func (o serveOptions) listenAt() (network, address string) {
	if !o.listen.IsValid() {
		return "tcp", "127.0.0.1:" + o.port
	}
	return listenNetwork(o.listen), net.JoinHostPort(o.listen.String(), o.port)
}

// listensOnLoopback is whether the address listenAt names is a loopback
// address, which gateway posture reports for serve's command line without
// binding it: 127.0.0.1 where --listen names none, and otherwise the IP
// address --listen names, written out, so no resolver is asked.
func (o serveOptions) listensOnLoopback() bool {
	return !o.listen.IsValid() || o.listen.IsLoopback()
}

// serveListen binds. A test stands in for it, to see what the start writes
// for an address the test must not bind. It is a package variable, so a
// test that replaces it must not run in parallel with another that
// starts serve, and must put it back.
var serveListen = net.Listen

// listenForServe binds where serve from the command line listens. When
// what it bound is not a loopback address it writes offLoopbackNote on
// stderr, before the readiness line, so the line is there whenever the
// gateway is reachable from other hosts. A loopback address writes nothing,
// and the start's output is what it was before --listen.
func listenForServe(opts serveOptions, stderr io.Writer) (net.Listener, error) {
	network, address := opts.listenAt()
	listener, err := serveListen(network, address)
	if err != nil {
		return nil, err
	}
	if !boundToLoopback(listener.Addr()) {
		fmt.Fprintln(stderr, offLoopbackNote(listener.Addr()))
	}
	return listener, nil
}

// boundToLoopback says whether a bound address is a loopback address. One
// that is not a TCP address on a loopback IP is taken as reachable.
func boundToLoopback(addr net.Addr) bool {
	tcp, ok := addr.(*net.TCPAddr)
	return ok && tcp.IP.IsLoopback()
}

// offLoopbackNote is the start's line for a listener other hosts can
// reach, naming the address bound.
func offLoopbackNote(addr net.Addr) string {
	return fmt.Sprintf("start: listening on %s, which is not a loopback address: other hosts can reach this gateway, "+
		"and it authenticates no caller, so whoever reaches it can run its sources and have receipts and seals signed under its key", addr)
}

// listenForConfig binds where serve --config listens: the configuration's
// listen, as engineListen held it. A loopback address is bound as it always
// was, "tcp" at the address, and writes nothing. One that is not loopback
// is bound in its own family (listenNetwork), as --listen's is, and when
// what was bound is not a loopback address otherHostsConfigNote is written
// on stderr, before the readiness line. A listen this cannot read as an
// address and a port, which the configuration never holds, is refused
// rather than bound in both families.
func listenForConfig(listen string, stderr io.Writer) (net.Listener, error) {
	network := "tcp"
	if !listenIsLoopback(listen) {
		at, err := netip.ParseAddrPort(listen)
		if err != nil {
			return nil, fmt.Errorf("listen %q is not an IP address and a port", listen)
		}
		network = listenNetwork(at.Addr())
	}
	listener, err := serveListen(network, listen)
	if err != nil {
		return nil, err
	}
	if !boundToLoopback(listener.Addr()) {
		fmt.Fprintln(stderr, otherHostsConfigNote(listener.Addr()))
	}
	return listener, nil
}

// otherHostsConfigNote is serve --config's line for a listener other hosts
// can reach, naming the address bound. That form authenticates its callers,
// so the line says what the token is worth over the transport, and not
// that nobody is authenticated.
func otherHostsConfigNote(addr net.Addr) string {
	return fmt.Sprintf("start: listening on %s, which is not a loopback address: other hosts can reach this gateway; "+
		"it holds every caller but those of /registry and /publickey to a token, and speaks plain HTTP, "+
		"so unless TLS terminates in front of it a token can be read and replayed on the network between", addr)
}
