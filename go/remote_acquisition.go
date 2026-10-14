package main

// The members a remote MCP server adds to an acquisition (SPEC.md §1.2a and
// §6, shape mcp; docs/adr/0015-a-remote-mcp-server-as-a-source-and-executor.md):
// `transport` and `server`, present together, on shape mcp alone, with the
// endpoint and the peer identity then held to the forms a remote server's
// take. The signer holds an adapter's envelope to them, the verifier a
// receipt, and a binding's remote server is held to the endpoint's form
// before the engine starts. A write to a remote server names its transport
// in the action's tool, whose endpoint is then held to the same form (#268).

import (
	"errors"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// maxRemoteEndpoint is the longest endpoint a remote server is named by.
const maxRemoteEndpoint = 2048

// remoteEndpointForm is the endpoint form in the words a refusal gives an
// operator.
const remoteEndpointForm = "https, or http at a loopback address written as one (127.0.0.0/8 in dotted decimal, or [::1]); " +
	"a host of letters, digits, '-', '.' and '_', or an IPv6 address in brackets; a port, when given, from 1 to 65535 with no leading zero; " +
	"no user, query or fragment; every '%' followed by two hexadecimal digits; at most 2048 characters of printable ASCII (SPEC.md §1.2a)"

var (
	remotePeerIdentity = regexp.MustCompile(`^tls:sha256:[0-9a-f]{64}$`)
	// endpointName and endpointBracketed are the two ways a remote
	// endpoint's host is written: a name, an IPv4 address in dotted
	// decimal among them, and an address in brackets, whose characters are
	// these and which is an IPv6 address besides (isIPv6Address). Neither
	// holds "@", so no user is named before the host.
	endpointName      = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	endpointBracketed = regexp.MustCompile(`^\[[0-9A-Fa-f:.]+\]$`)
)

// isRemoteEndpoint is the form of a remote MCP server's endpoint, as
// SPEC.md §1.2a states it once for the signer, both verifiers and the
// adapter, each tested against one table (testdata/remote-endpoints/cases.json):
// at most 2048 characters, each from U+0021 to U+007E, no "?" and no "#";
// "https://" or "http://"; then an authority, a host and optionally ":" and
// a port; then nothing, or "/" and a path. The host is a name of letters,
// digits, "-", "." and "_", or "[", an IPv6 address, and "]", so no "@" is
// in the authority and no user is named; the port a
// decimal from 1 to 65535 with no leading zero; and every "%" in the path is
// followed by exactly two hexadecimal digits. An "@" in the path names no
// user, and is a path's character like any other. After "http://", the host is a loopback address
// written as one, an IPv4 address of 127.0.0.0/8 in dotted decimal or
// [::1]; a name is not one, localhost included.
func isRemoteEndpoint(s string) bool {
	if len(s) > maxRemoteEndpoint {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	if strings.ContainsAny(s, "?#") {
		return false
	}
	rest, secure := strings.CutPrefix(s, "https://")
	if !secure {
		var plain bool
		if rest, plain = strings.CutPrefix(s, "http://"); !plain {
			return false
		}
	}
	authority, path, _ := strings.Cut(rest, "/")
	host, port, hasPort, ok := endpointAuthority(authority)
	if !ok || host == "" {
		return false
	}
	if !endpointName.MatchString(host) && !endpointBracketed.MatchString(host) {
		return false
	}
	if endpointBracketed.MatchString(host) && !isIPv6Address(host[1:len(host)-1]) {
		return false
	}
	if hasPort && !isEndpointPort(port) {
		return false
	}
	if !isEndpointPath(path) {
		return false
	}
	return secure || isLoopbackHost(host)
}

// endpointAuthority is an authority's host and its port: a host in
// brackets runs to the first "]", any other to the first ":"; hasPort is
// whether ":" follows the host. ok is false when anything else follows a
// host in brackets, or the "]" is missing.
func endpointAuthority(authority string) (host, port string, hasPort, ok bool) {
	if !strings.HasPrefix(authority, "[") {
		host, port, hasPort = strings.Cut(authority, ":")
		return host, port, hasPort, true
	}
	end := strings.IndexByte(authority, ']')
	if end < 0 {
		return "", "", false, false
	}
	host, rest := authority[:end+1], authority[end+1:]
	if rest == "" {
		return host, "", false, true
	}
	port, hasPort = strings.CutPrefix(rest, ":")
	return host, port, hasPort, hasPort
}

// isIPv6Address is an IPv6 address in the form RFC 3986 names IPv6address
// (SPEC.md §1.2a): eight groups of one to four hexadecimal digits separated
// by ":", "::" standing once for one or more groups of zeros, the last two
// groups optionally an IPv4 address in dotted decimal, each part from 0 to
// 255 with no leading zero; no zone. netip.ParseAddr reads exactly that
// form, a zone besides, and an IPv4 address on its own: both are refused
// here. testdata/remote-endpoints/cases.json holds it to the form on each
// side.
func isIPv6Address(s string) bool {
	addr, err := netip.ParseAddr(s)
	return err == nil && addr.Is6() && addr.Zone() == ""
}

// isEndpointPort is a port in decimal from 1 to 65535 with no leading zero;
// an empty one is not.
func isEndpointPort(port string) bool {
	if !originPort.MatchString(port) {
		return false
	}
	n, err := strconv.Atoi(port)
	return err == nil && n <= 65535
}

// isEndpointPath is a path in which every "%" is followed by exactly two
// hexadecimal digits.
func isEndpointPath(path string) bool {
	for i := 0; i < len(path); i++ {
		if path[i] == '%' && (i+2 >= len(path) || !isHexDigit(path[i+1]) || !isHexDigit(path[i+2])) {
			return false
		}
	}
	return true
}

func isHexDigit(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

// toolTransportProblem holds an action's tool to what a write to a remote
// server adds to it (SPEC.md §1.2a, #268), or is nil when it adds nothing:
// transport, when present, is "http", on shape mcp alone, and the endpoint
// is then a string of the endpoint form above. Without transport the
// endpoint is the platform's, a string or null as the engine configuration
// takes it, and is held to nothing here: a stdio write's endpoint may even
// begin with "https://", so its spelling says nothing of the transport.
func toolTransportProblem(tool *vObject) error {
	transport, present := tool.get("transport")
	if !present {
		return nil
	}
	if t, ok := transport.(vString); !ok || t != "http" {
		return errors.New("action.tool: transport is outside its enumeration")
	}
	if shape, _ := memberString(tool, "shape"); shape != "mcp" {
		return errors.New("action.tool: transport is a member of shape mcp alone")
	}
	endpoint, ok := memberString(tool, "endpoint")
	if !ok || !isRemoteEndpoint(endpoint) {
		return errors.New("action.tool: a remote server's endpoint is not of its form")
	}
	return nil
}

// remoteMembersOnShape is why an acquisition of the shape given carries what
// only an mcp adapter reaching a remote server reports, or nil.
func remoteMembersOnShape(acquisition *vObject, shape string) error {
	_, hasTransport := acquisition.get("transport")
	_, hasServer := acquisition.get("server")
	if shape != "mcp" && (hasTransport || hasServer) {
		return errors.New("acquisition: transport and server are members of shape mcp alone")
	}
	return nil
}

// remoteMembersProblem holds what a remote MCP server adds to an
// acquisition, or nil when neither member is there: transport and server
// together, on shape mcp alone; transport "http"; server an object of a
// string name and a string version -- exactly those, where exact says so,
// as the signer reads an envelope, and tolerating others as a verifier
// tolerates any member it does not know; the endpoint of the form above;
// and the peer identity "tls:sha256:" and 64 lowercase hex after
// "https://", null after "http://", where no transport identity is
// established.
func remoteMembersProblem(acquisition *vObject, shape string, exact bool) error {
	transport, hasTransport := acquisition.get("transport")
	server, hasServer := acquisition.get("server")
	if !hasTransport && !hasServer {
		return nil
	}
	if !hasTransport || !hasServer {
		return errors.New("acquisition: transport and server are present together or not at all")
	}
	if shape != "mcp" {
		return errors.New("acquisition: transport and server are members of shape mcp alone")
	}
	if t, ok := transport.(vString); !ok || t != "http" {
		return errors.New("acquisition: transport is outside its enumeration")
	}
	obj, err := requireObject(server, "acquisition.server")
	if err != nil {
		return err
	}
	for _, member := range []string{"name", "version"} {
		if _, err := requireString(obj, member); err != nil {
			return errors.New("acquisition.server: " + err.Error())
		}
	}
	if exact {
		if err := exactlyMembers(obj, map[string]bool{"name": true, "version": true}, "acquisition.server"); err != nil {
			return err
		}
	}
	endpoint, ok := memberString(acquisition, "endpoint")
	if !ok || !isRemoteEndpoint(endpoint) {
		return errors.New("acquisition: a remote server's endpoint is not of its form")
	}
	peer, _ := acquisition.get("peerIdentity")
	if strings.HasPrefix(endpoint, "https://") {
		if s, ok := peer.(vString); !ok || !remotePeerIdentity.MatchString(string(s)) {
			return errors.New("acquisition: a remote server reached over TLS is named by tls:sha256: and the digest of its certificate")
		}
	} else if _, isNull := peer.(vNull); !isNull {
		return errors.New("acquisition: a remote server reached in the clear establishes no peer identity")
	}
	return nil
}
