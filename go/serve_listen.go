package main

// Where `gateway serve` from the command line listens (#387): 127.0.0.1 at
// --port, as it always has, or the address --listen names. That form of
// serve has no identity, so it authenticates no caller: whoever reaches the
// listener can run its sources and have receipts and seals signed under its
// key. An address other hosts can reach is therefore taken only with
// --accept-unauthenticated-callers beside it, and the start says on stderr
// that it listens there. `serve --config` is not changed: its `listen` is
// held to a loopback address by the configuration (engine.go,
// loopbackAddress).

import (
	"fmt"
	"io"
	"net"
	"net/netip"
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
	addr, err := netip.ParseAddr(written)
	if err != nil || addr.Zone() != "" {
		return netip.Addr{}, fmt.Sprintf("--listen %q is not an IP address alone: IPv4 in dotted decimal, or IPv6 bare or in brackets, with no zone and no port; a name is not one, localhost included", value), false
	}
	// An IPv4 address in IPv6 form is the IPv4 address; brackets are IPv6's.
	canonical := addr.Unmap()
	if canonical.String() != written || (bracketed && !canonical.Is6()) {
		return netip.Addr{}, fmt.Sprintf("--listen %q is the address %s written another way; give it as %s", value, canonical, canonical), false
	}
	return canonical, "", true
}

// listenAt is the network and the address serve from the command line
// binds. With no --listen it is 127.0.0.1 at --port, with the network it
// has always been bound with. With one it is the address named, in that
// address's own family, so that 0.0.0.0 binds every IPv4 address and no
// IPv6 one, and :: every IPv6 address and no IPv4 one; "tcp" would bind
// both for either.
func (o serveOptions) listenAt() (network, address string) {
	if !o.listen.IsValid() {
		return "tcp", "127.0.0.1:" + o.port
	}
	network = "tcp4"
	if o.listen.Is6() {
		network = "tcp6"
	}
	return network, net.JoinHostPort(o.listen.String(), o.port)
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
