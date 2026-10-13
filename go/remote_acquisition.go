package main

// The members a remote MCP server adds to an acquisition (SPEC.md §1.2a and
// §6, shape mcp; docs/adr/0015-a-remote-mcp-server-as-a-source-and-executor.md):
// `transport` and `server`, present together, on shape mcp alone, with the
// endpoint and the peer identity then held to the forms a remote server's
// take. The signer holds an adapter's envelope to them, the verifier a
// receipt, and a binding's remote server is held to the endpoint's form
// before the engine starts.

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
)

// maxRemoteEndpoint is the longest endpoint a remote server is named by.
const maxRemoteEndpoint = 2048

var remotePeerIdentity = regexp.MustCompile(`^tls:sha256:[0-9a-f]{64}$`)

// isRemoteEndpoint is the form of a remote MCP server's endpoint: at most
// 2048 characters, each from U+0021 to U+007E; "https://" or "http://"
// first; no "?" and no "#"; an authority -- what follows "//" up to the
// first "/" or the end -- that is not empty and holds no "@"; and, after
// "http://", an authority that is a loopback address written as one, an
// IPv4 address of 127.0.0.0/8 in dotted decimal or [::1], with ":" and a
// port in decimal from 1 to 65535 with no leading zero, or no port.
func isRemoteEndpoint(s string) bool {
	if s == "" || len(s) > maxRemoteEndpoint {
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
	authority, _, _ := strings.Cut(rest, "/")
	if authority == "" || strings.Contains(authority, "@") {
		return false
	}
	return secure || isLoopbackAuthority(authority)
}

// isLoopbackAuthority is a loopback address written as one, with a port or
// without.
func isLoopbackAuthority(authority string) bool {
	host, port, hasPort := authority, "", false
	if strings.HasPrefix(authority, "[") {
		end := strings.IndexByte(authority, ']')
		if end < 0 {
			return false
		}
		host = authority[:end+1]
		if rest := authority[end+1:]; rest != "" {
			if port, hasPort = strings.CutPrefix(rest, ":"); !hasPort {
				return false
			}
		}
	} else {
		host, port, hasPort = strings.Cut(authority, ":")
	}
	if hasPort {
		if !originPort.MatchString(port) {
			return false
		}
		if n, err := strconv.Atoi(port); err != nil || n > 65535 {
			return false
		}
	}
	return isLoopbackHost(host)
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
