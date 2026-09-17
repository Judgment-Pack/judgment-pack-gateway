package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// The engine's one configuration file (docs/design/engine-config.md): it
// names platforms, credentials, the store and the signer's identity, never a
// process, and `serve --config` derives every source from it. It is read
// through the same strict parser as everything else -- duplicate names
// refused, integers only, unknown members refused by name -- so a
// misspelled key is an error, never an intention silently dropped.

// engineVersion is the newest version this engine reads; engineVersions are
// all it reads. Version 2 adds the optional `mcp` member (docs/design/
// mcp-server.md), and version 3 a platform's optional `descriptors` pin
// (docs/design/tool-descriptors.md): a file of an earlier version without
// the member still loads, and one with it is refused by name, as any member
// a version does not have. connect writes version 3 into a file exactly
// when the entry it writes carries a pin, and otherwise leaves the version
// as it found it.
const engineVersion = "3"

var engineVersions = map[string]bool{"1": true, "2": true, "3": true}

// The frontend's user (docs/design/mcp-server.md): the MCP server runs as
// it, so no platform may, or a credentials file could belong to the user
// that process runs as.
const (
	frontendUser = "engine-mcp"
	frontendUID  = 65533
)

const maxEngineConfigBytes = 1 << 20

type engineConfig struct {
	authority       string
	seed            string
	store           string
	registry        string
	decisionRecords string
	listen          string
	catalog         string
	runtime         string
	adapters        string
	rootSigner      bool
	hostRuntime     bool
	identity        *identitySpec    // who may call; nil records caller null
	platforms       []platformConfig // in name order
	version         string
	mcp             *mcpConfig // the MCP server's own settings; nil when the configuration has none
}

// mcpConfig is the `mcp` member (docs/design/mcp-server.md): where the MCP
// server listens, the resource it is reached as, the origins its HTTP
// transport admits, and its bounds.
type mcpConfig struct {
	listen         string
	resource       string   // the protected resource's identifier; "" when not given
	origins        []string // exact origins, when given
	originsGiven   bool     // the member was present, even empty; absent means loopback origins
	sessions       int
	idleSeconds    int
	concurrency    int
	callsPerMinute int
}

var mcpMembers = map[string]bool{
	"listen": true, "resource": false, "origins": false,
	"sessions": false, "idleSeconds": false, "concurrency": false, "callsPerMinute": false,
}

// mcpBounds are the four bounds' defaults and ranges, in the note's order.
var mcpBounds = []struct {
	name          string
	def, min, max int
	into          func(*mcpConfig) *int
}{
	{"sessions", 64, 1, 4096, func(m *mcpConfig) *int { return &m.sessions }},
	{"idleSeconds", 1800, 60, 86400, func(m *mcpConfig) *int { return &m.idleSeconds }},
	{"concurrency", 8, 1, 64, func(m *mcpConfig) *int { return &m.concurrency }},
	{"callsPerMinute", 120, 1, 6000, func(m *mcpConfig) *int { return &m.callsPerMinute }},
}

type platformConfig struct {
	name        string
	binding     string            // name@sha256:hex
	credentials map[string]string // by operation (history, live): a path, never a value
	user        string
	uid         int    // resolved from the user database
	home        string // the user's home, from the user database
	endpoint    string
	environment []string // KEY=VALUE, for the runtime's selection, never a secret
	write       bool
	// descriptors pins the snapshot of the live operation's tool
	// descriptors that connect captured, sha256:<64 hex>; "" when none. The
	// signer never reads it; the frontend does (tool-descriptors.md).
	descriptors string
}

// identitySpec is the identity member as written: the token issuer, the
// audience this engine is named as, and the file holding the issuer's
// public keys, read when the configuration is loaded and never fetched.
type identitySpec struct {
	issuer   string
	audience string
	keys     string // an absolute path to a JSON Web Key Set
}

// binding is a catalog entry: which pinned artifact serves which operation
// of a platform, with the licence of each stated.
type binding struct {
	platform string
	history  *operation
	live     *operation
	// write is the operation an executor is pointed at (executor.md): the
	// same mcp shape as live, its own tools, its own credentials. Stated in
	// the binding and derived only for a platform whose configuration sets
	// write: true.
	write *operation
}

type operation struct {
	shape string
	image string
	args  []string // the server's own arguments inside its container (mcp)
	tools []string
	probe string // a tool a check calls once to reach the platform (mcp)
	// probeFailure is text the probe's answer begins with when the
	// platform was not reached, for a server that answers its own failure
	// as ordinary text.
	probeFailure string
	licence      string
}

// engineHost is what the engine asks the operating system while it holds
// a configuration to the isolation claim: who it runs as, what it may do,
// who owns a file, who a user is. Tests stand each in.
type engineHost struct {
	euid         int
	sockets      func(runtime string) []string
	capabilities func() capabilitySets
	fileOwner    func(path string) (fileOwnership, error)
	readLink     func(path string) (string, error) // where a symbolic link points
	account      func(name string) (uid int, home string, err error)
	// switching is why this process could not run the sources as the
	// users they name -- the requirement serve holds every source to
	// at start (requireUserSwitching) -- or nil.
	switching func(sources map[string]sourceSpec) error
	// executable is this binary as the kernel sees it (exeFacts).
	executable func() (exeFacts, error)
}

// exeFacts is what the engine knows about its own binary: its path, its
// permission bits, and whether it carries file capabilities, which make it
// a file that grants privilege to whoever executes it.
type exeFacts struct {
	path         string
	mode         os.FileMode
	capabilities bool
}

type fileOwnership struct {
	uid    int
	mode   os.FileMode // permission bits
	dir    bool
	link   bool // a symbolic link, judged as itself and not as its target
	sticky bool // a directory in which only a file's owner may remove or rename it
}

// engineMembers lists every member the configuration may carry and whether
// it must.
var engineMembers = map[string]bool{
	"engineVersion": true, "authority": true, "seed": true, "store": true, "registry": true,
	"decisionRecords": true, "listen": true, "catalog": true, "platforms": true,
	"runtime": false, "adapters": false, "rootSigner": false, "hostRuntime": false, "identity": false,
	"mcp": false,
}

var platformMembers = map[string]bool{
	"binding": true, "credentials": true, "user": true,
	"endpoint": false, "environment": false, "write": false, "descriptors": false,
}

// parseEngineConfig holds the file to the shape the design note states.
func parseEngineConfig(data []byte) (engineConfig, error) {
	v, err := parseJSON(data)
	if err != nil {
		return engineConfig{}, fmt.Errorf("engine configuration: %v", err)
	}
	obj, ok := v.(*vObject)
	if !ok {
		return engineConfig{}, errors.New("engine configuration: not an object")
	}
	if err := exactlyMembers(obj, engineMembers, "engine configuration"); err != nil {
		return engineConfig{}, err
	}
	var cfg engineConfig
	version, _ := memberString(obj, "engineVersion")
	if !engineVersions[version] {
		return engineConfig{}, fmt.Errorf("engine configuration: engineVersion %q is not %q, %q or %q", version, "1", "2", engineVersion)
	}
	cfg.version = version
	if _, present := obj.get("mcp"); present && version == "1" {
		return engineConfig{}, errors.New("engine configuration: mcp is a version-2 member; engineVersion 1 has no mcp")
	}
	authority, err := requireString(obj, "authority")
	if err != nil || authority == "" {
		return engineConfig{}, errors.New("engine configuration: authority must be a non-empty string")
	}
	cfg.authority = authority
	// Every path is absolute: a path relative to wherever the engine was
	// started names nothing an operator can reason about.
	for _, m := range []struct {
		name string
		into *string
	}{
		{"seed", &cfg.seed}, {"store", &cfg.store}, {"registry", &cfg.registry},
		{"decisionRecords", &cfg.decisionRecords}, {"catalog", &cfg.catalog},
	} {
		s, err := requireAbsolutePath(obj, m.name)
		if err != nil {
			return engineConfig{}, fmt.Errorf("engine configuration: %v", err)
		}
		*m.into = s
	}
	if identityValue, present := obj.get("identity"); present {
		identity, err := requireObject(identityValue, "identity")
		if err != nil {
			return engineConfig{}, fmt.Errorf("engine configuration: %v", err)
		}
		if err := exactlyMembers(identity, map[string]bool{"issuer": true, "audience": true, "keys": true}, "identity"); err != nil {
			return engineConfig{}, err
		}
		spec := &identitySpec{}
		if spec.issuer, err = requireString(identity, "issuer"); err != nil || spec.issuer == "" {
			return engineConfig{}, errors.New("engine configuration: identity.issuer must be the token issuer, as its tokens name it")
		}
		if spec.audience, err = requireString(identity, "audience"); err != nil || spec.audience == "" {
			return engineConfig{}, errors.New("engine configuration: identity.audience must be the audience this engine is named as in a token")
		}
		if spec.keys, err = requireAbsolutePath(identity, "keys"); err != nil {
			return engineConfig{}, fmt.Errorf("engine configuration: identity.%v", err)
		}
		cfg.identity = spec
	}
	cfg.runtime = "docker"
	if _, present := obj.get("runtime"); present {
		s, err := requireString(obj, "runtime")
		if err != nil || s == "" {
			return engineConfig{}, errors.New("engine configuration: runtime must be a non-empty string, the container runtime command (docker or podman)")
		}
		cfg.runtime = s
	}
	if _, present := obj.get("adapters"); present {
		s, err := requireAbsolutePath(obj, "adapters")
		if err != nil {
			return engineConfig{}, fmt.Errorf("engine configuration: %v", err)
		}
		cfg.adapters = s
	}
	for _, name := range []string{"rootSigner", "hostRuntime"} {
		if _, present := obj.get(name); !present {
			continue
		}
		s, err := requireString(obj, name)
		if err != nil || s != "accepted" {
			return engineConfig{}, fmt.Errorf(`engine configuration: %s, when present, is the string "accepted" and nothing else`, name)
		}
		if name == "rootSigner" {
			cfg.rootSigner = true
		} else {
			cfg.hostRuntime = true
		}
	}
	listen, err := requireString(obj, "listen")
	if err != nil {
		return engineConfig{}, errors.New("engine configuration: listen must be a string")
	}
	if cfg.listen, err = loopbackAddress(listen); err != nil {
		return engineConfig{}, fmt.Errorf("engine configuration: %v", err)
	}
	if mcpValue, present := obj.get("mcp"); present {
		m, err := parseMCPConfig(mcpValue)
		if err != nil {
			return engineConfig{}, fmt.Errorf("engine configuration: %v", err)
		}
		// The frontend finds the signer by the configured address and
		// nothing else, so an address the kernel picks is no address.
		if portIsZero(cfg.listen) {
			return engineConfig{}, errors.New("engine configuration: listen names port 0, which the MCP server cannot find the signer by; with mcp present the signer's port is explicit")
		}
		cfg.mcp = m
	}
	platformsValue, _ := obj.get("platforms")
	platforms, err := requireObject(platformsValue, "platforms")
	if err != nil {
		return engineConfig{}, fmt.Errorf("engine configuration: %v", err)
	}
	// An empty platforms object parses: it is what a configuration looks
	// like before its first `connect`, and serving it is refused where the
	// configuration is held to what it must name (engineRefusals).
	names := append([]string(nil), platforms.names...)
	sort.Strings(names)
	for _, name := range names {
		if err := validPlatformName(name); err != nil {
			return engineConfig{}, fmt.Errorf("engine configuration: %v", err)
		}
		raw, _ := platforms.get(name)
		p, err := requireObject(raw, "platform "+name)
		if err != nil {
			return engineConfig{}, fmt.Errorf("engine configuration: %v", err)
		}
		if err := exactlyMembers(p, platformMembers, "platform "+name); err != nil {
			return engineConfig{}, err
		}
		pc := platformConfig{name: name}
		if pc.binding, err = requireString(p, "binding"); err != nil || !isBindingRef(pc.binding) {
			return engineConfig{}, fmt.Errorf("engine configuration: platform %s: binding must be name@sha256:<64 hex>, the name a catalog file's without / or \\", name)
		}
		// One credentials file per operation: a connector's configuration
		// and a server's environment are different files, and a binding's
		// operations each name theirs. Which operations must be named is
		// the binding's to say (resolveEngineConfig).
		credentialsValue, _ := p.get("credentials")
		credentials, err := requireObject(credentialsValue, "credentials")
		if err != nil {
			return engineConfig{}, fmt.Errorf("engine configuration: platform %s: %v", name, err)
		}
		if err := exactlyMembers(credentials, map[string]bool{"history": false, "live": false, "write": false}, "platform "+name+" credentials"); err != nil {
			return engineConfig{}, err
		}
		if len(credentials.names) == 0 {
			return engineConfig{}, fmt.Errorf("engine configuration: platform %s: credentials names no operation", name)
		}
		pc.credentials = map[string]string{}
		for _, op := range credentials.names {
			raw, _ := credentials.get(op)
			entry, err := requireObject(raw, "credentials."+op)
			if err != nil {
				return engineConfig{}, fmt.Errorf("engine configuration: platform %s: %v", name, err)
			}
			if err := exactlyMembers(entry, map[string]bool{"file": true}, "platform "+name+" credentials."+op); err != nil {
				return engineConfig{}, err
			}
			if pc.credentials[op], err = requireAbsolutePath(entry, "file"); err != nil {
				return engineConfig{}, fmt.Errorf("engine configuration: platform %s: credentials.%s.%v", name, op, err)
			}
		}
		if pc.user, err = requireString(p, "user"); err != nil || pc.user == "" {
			return engineConfig{}, fmt.Errorf("engine configuration: platform %s: user must name the OS user its adapters run as; an adapter running as the signer could read the seed", name)
		}
		if _, present := p.get("endpoint"); present {
			if pc.endpoint, err = requireString(p, "endpoint"); err != nil || pc.endpoint == "" {
				return engineConfig{}, fmt.Errorf("engine configuration: platform %s: endpoint, when present, is a non-empty string", name)
			}
		}
		if envValue, present := p.get("environment"); present {
			env, err := requireObject(envValue, "environment")
			if err != nil {
				return engineConfig{}, fmt.Errorf("engine configuration: platform %s: %v", name, err)
			}
			for _, key := range env.names {
				value, ok := memberString(env, key)
				if !ok || key == "" || strings.ContainsAny(key, "=\x00") || strings.ContainsAny(value, "\n\x00") {
					return engineConfig{}, fmt.Errorf("engine configuration: platform %s: environment.%s must be a string value under a variable name", name, key)
				}
				if sameEnvKey(key, "HOME") || sameEnvKey(key, "PATH") {
					return engineConfig{}, fmt.Errorf("engine configuration: platform %s: environment may not set %s; HOME is the user's own and PATH the engine's", name, key)
				}
				pc.environment = append(pc.environment, key+"="+value)
			}
		}
		if w, present := p.get("write"); present {
			b, ok := w.(vBool)
			if !ok {
				return engineConfig{}, fmt.Errorf("engine configuration: platform %s: write, when present, is a boolean", name)
			}
			pc.write = bool(b)
		}
		if _, present := p.get("descriptors"); present {
			if version != "3" {
				return engineConfig{}, fmt.Errorf("engine configuration: platform %s: descriptors is a version-3 member; engineVersion %s has no descriptors", name, version)
			}
			pin, ok := memberString(p, "descriptors")
			if !ok || !isDigest(pin) {
				return engineConfig{}, fmt.Errorf("engine configuration: platform %s: descriptors must be sha256:<64 lowercase hex>, the digest of a snapshot", name)
			}
			pc.descriptors = pin
		}
		cfg.platforms = append(cfg.platforms, pc)
	}
	return cfg, nil
}

// parseMCPConfig holds the `mcp` member to the note's shape: a loopback
// listen address with an explicit port, a resource identifier that is an
// absolute https URL without a fragment, exact origins, and the four
// bounds within their ranges.
func parseMCPConfig(v value) (*mcpConfig, error) {
	obj, err := requireObject(v, "mcp")
	if err != nil {
		return nil, err
	}
	if err := exactlyMembers(obj, mcpMembers, "mcp"); err != nil {
		return nil, err
	}
	m := &mcpConfig{}
	listen, err := requireString(obj, "listen")
	if err != nil {
		return nil, errors.New("mcp.listen must be a string")
	}
	if m.listen, err = loopbackAddress(listen); err != nil {
		return nil, fmt.Errorf("mcp.%v", err)
	}
	if portIsZero(m.listen) {
		return nil, errors.New("mcp.listen names port 0; the MCP server's port is explicit, since the resource it is reached as names it")
	}
	if _, present := obj.get("resource"); present {
		s, err := requireString(obj, "resource")
		if err != nil {
			return nil, errors.New("mcp.resource must be a string")
		}
		if err := validResourceURL(s); err != nil {
			return nil, fmt.Errorf("mcp.resource: %v", err)
		}
		m.resource = s
	}
	if originsValue, present := obj.get("origins"); present {
		arr, ok := originsValue.(vArray)
		if !ok {
			return nil, errors.New("mcp.origins must be an array of origins")
		}
		// present and empty is a statement: no origin at all is admitted
		m.originsGiven = true
		for _, item := range arr {
			s, ok := item.(vString)
			if !ok {
				return nil, errors.New("mcp.origins must be an array of origins, each a string")
			}
			if err := validOrigin(string(s)); err != nil {
				return nil, fmt.Errorf("mcp.origins: %v", err)
			}
			m.origins = append(m.origins, string(s))
		}
	}
	for _, b := range mcpBounds {
		*b.into(m) = b.def
		n, present, err := integerMember(obj, b.name)
		if err != nil {
			return nil, fmt.Errorf("mcp.%s must be an integer", b.name)
		}
		if !present {
			continue
		}
		if n < int64(b.min) || n > int64(b.max) {
			return nil, fmt.Errorf("mcp.%s %d is outside %d to %d", b.name, n, b.min, b.max)
		}
		*b.into(m) = int(n)
	}
	return m, nil
}

// validResourceURL is what a protected resource's identifier must be
// (RFC 9728, RFC 8707): an absolute https URL with a host and no fragment.
func validResourceURL(s string) error {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Fragment != "" || u.RawFragment != "" || strings.Contains(s, "#") {
		return fmt.Errorf("%q is not an absolute https URL without a fragment", s)
	}
	return nil
}

// validIssuerURL is what an authorization server's identifier must be
// (RFC 8414 §2): an absolute https URL with no query and no fragment.
func validIssuerURL(s string) error {
	if err := validResourceURL(s); err != nil {
		return err
	}
	if strings.ContainsAny(s, "?#") {
		return fmt.Errorf("%q carries a query or a fragment, which an issuer identifier may not", s)
	}
	return nil
}

// validOrigin is an origin as a browser sends it: scheme://host[:port],
// nothing more -- no path, no query or fragment delimiter even empty, no
// userinfo, no trailing slash.
func validOrigin(s string) error {
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.Path != "" || u.User != nil || strings.HasSuffix(s, "/") || strings.ContainsAny(s, "?#") || u.Opaque != "" {
		return fmt.Errorf("%q is not an origin (scheme://host[:port])", s)
	}
	return nil
}

func requireAbsolutePath(obj *vObject, name string) (string, error) {
	s, err := requireString(obj, name)
	if err != nil || s == "" {
		return "", fmt.Errorf("%s must be a non-empty absolute path", name)
	}
	return cleanAbsolutePath(name, s)
}

// validPlatformName is why a platform name cannot be one, or nil: it is a
// source name's first segment, an environment value and a word an operator
// reads, so it is neither empty nor padded, holds no separator, and is
// made of graphic characters -- no control character, no line break, no
// escape that a terminal would act on.
func validPlatformName(name string) error {
	if strings.ContainsAny(name, "/=\x00") || strings.TrimSpace(name) == "" || name != strings.TrimSpace(name) {
		return fmt.Errorf("platform name %q may not be empty, padded, or contain / or =", name)
	}
	for _, r := range name {
		if !unicode.IsGraphic(r) {
			return fmt.Errorf("platform name %q may not contain a control or other non-graphic character", name)
		}
	}
	return nil
}

// cleanAbsolutePath holds a configured path to being absolute and clean.
func cleanAbsolutePath(name, s string) (string, error) {
	if s == "" {
		return "", fmt.Errorf("%s must be a non-empty absolute path", name)
	}
	if !filepath.IsAbs(s) {
		return "", fmt.Errorf("%s must be an absolute path, not %q", name, s)
	}
	// Clean as written: a "." or ".." component, or a doubled separator,
	// would be resolved by a walk in a way a reader of the file cannot see.
	if filepath.Clean(s) != s {
		return "", fmt.Errorf("%s must be a clean path, without . or .. components or a trailing separator, not %q", name, s)
	}
	return s, nil
}

// exactlyMembers refuses a member the shape does not name and a required
// one that is absent.
func exactlyMembers(obj *vObject, members map[string]bool, what string) error {
	for _, name := range obj.names {
		if _, known := members[name]; !known {
			return fmt.Errorf("%s: unknown member %q", what, name)
		}
	}
	for name, required := range members {
		if _, present := obj.get(name); required && !present {
			return fmt.Errorf("%s: missing member %q", what, name)
		}
	}
	return nil
}

// loopbackAddress holds listen to a literal loopback address with a valid
// port: 127.0.0.1 or ::1, never a name that a resolver may map elsewhere.
// The gateway speaks plain HTTP, and reaching it from another host is a
// front the operator runs. The address comes back in one spelling: the
// IP as the parser prints it, the port as a number.
func loopbackAddress(listen string) (string, error) {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "", fmt.Errorf("listen %q is not host:port", listen)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return "", fmt.Errorf("listen %q is not a literal loopback address; the engine listens on 127.0.0.1 or ::1 only", listen)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 0 || n > 65535 || strings.TrimSpace(port) != port || strings.HasPrefix(port, "+") || strings.HasPrefix(port, "-") {
		return "", fmt.Errorf("listen %q has no valid port", listen)
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(n)), nil
}

// portIsZero says whether a listen address names port zero, by its number
// and not its spelling: "00" is as much port zero as "0".
func portIsZero(listen string) bool {
	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		return false
	}
	n, err := strconv.Atoi(port)
	return err == nil && n == 0
}

func isBindingRef(ref string) bool {
	name, digest, ok := strings.Cut(ref, "@")
	return ok && name != "" && name == filepath.Base(name) && !strings.ContainsAny(name, "/\\@") && name != "." && name != ".." && isDigest(digest)
}

// loadBinding reads the catalog entry a platform names and holds it to the
// digest the configuration pinned: a catalog update never silently changes
// what a running engine reaches.
func loadBinding(catalog, ref string) (binding, error) {
	name, digest, _ := strings.Cut(ref, "@")
	path := filepath.Join(catalog, name+".json")
	data, err := readBounded(path, maxEngineConfigBytes)
	if err != nil {
		return binding{}, fmt.Errorf("binding %s: %v", ref, err)
	}
	sum := sha256.Sum256(data)
	if "sha256:"+hex.EncodeToString(sum[:]) != digest {
		return binding{}, fmt.Errorf("binding %s: %s does not digest to the pinned %s; the catalog changed under the configuration", ref, path, digest)
	}
	b, err := parseBinding(data)
	if err != nil {
		return binding{}, fmt.Errorf("binding %s: %v", ref, err)
	}
	if b.platform != name {
		return binding{}, fmt.Errorf("binding %s: the file names platform %q", ref, b.platform)
	}
	return b, nil
}

var bindingMembers = map[string]bool{"bindingVersion": true, "platform": true, "operations": true}

// parseBinding holds a catalog entry to its shape: one entry per operation,
// each naming its shape, a digest-pinned artifact, and its licence.
func parseBinding(data []byte) (binding, error) {
	v, err := parseJSON(data)
	if err != nil {
		return binding{}, err
	}
	obj, ok := v.(*vObject)
	if !ok {
		return binding{}, errors.New("not an object")
	}
	if err := exactlyMembers(obj, bindingMembers, "binding"); err != nil {
		return binding{}, err
	}
	if version, _ := memberString(obj, "bindingVersion"); version != "1" {
		return binding{}, fmt.Errorf("bindingVersion %q is not \"1\"", version)
	}
	var b binding
	if b.platform, err = requireString(obj, "platform"); err != nil || b.platform == "" {
		return binding{}, errors.New("platform must be a non-empty string")
	}
	opsValue, _ := obj.get("operations")
	ops, err := requireObject(opsValue, "operations")
	if err != nil {
		return binding{}, err
	}
	for _, name := range ops.names {
		raw, _ := ops.get(name)
		op, err := requireObject(raw, "operation "+name)
		if err != nil {
			return binding{}, err
		}
		parsed, err := parseOperation(op, name)
		if err != nil {
			return binding{}, err
		}
		switch name {
		case "history":
			if parsed.shape != "airbyte" {
				return binding{}, fmt.Errorf("operation history is served by the airbyte shape, not %q", parsed.shape)
			}
			b.history = &parsed
		case "live":
			if parsed.shape != "mcp" {
				return binding{}, fmt.Errorf("operation live is served by the mcp shape, not %q", parsed.shape)
			}
			b.live = &parsed
		case "write":
			if parsed.shape != "mcp" {
				return binding{}, fmt.Errorf("operation write is served by the mcp shape, not %q", parsed.shape)
			}
			if parsed.probe != "" {
				// A check of a write source starts the server, completes the
				// handshake and lists its tools, and calls nothing: a probe
				// would call a write tool, which no check may.
				return binding{}, errors.New("operation write accepts no probe: a write source's check calls no tool")
			}
			b.write = &parsed
		default:
			return binding{}, fmt.Errorf("unknown operation %q", name)
		}
	}
	if b.history == nil && b.live == nil {
		return binding{}, errors.New("no history or live operation")
	}
	return b, nil
}

func parseOperation(op *vObject, name string) (operation, error) {
	var o operation
	var err error
	if o.shape, err = requireString(op, "shape"); err != nil {
		return o, fmt.Errorf("operation %s: shape must be a string", name)
	}
	if o.licence, err = requireString(op, "licence"); err != nil || o.licence == "" {
		return o, fmt.Errorf("operation %s: licence must be stated", name)
	}
	switch o.shape {
	case "airbyte":
		// A streams restriction is not yet enforced at acquisition, so a
		// binding may not declare one: a restriction accepted and not
		// applied would read as applied.
		if err := exactlyMembers(op, map[string]bool{"shape": true, "image": true, "licence": true}, "operation "+name); err != nil {
			return o, err
		}
		if o.image, err = requireString(op, "image"); err != nil || !isPinnedImage(o.image) {
			return o, fmt.Errorf("operation %s: image must be pinned, name[:tag]@sha256:<64 hex>", name)
		}
	case "mcp":
		if err := exactlyMembers(op, map[string]bool{"shape": true, "server": true, "licence": true, "tools": true, "probe": false}, "operation "+name); err != nil {
			return o, err
		}
		serverValue, _ := op.get("server")
		server, err := requireObject(serverValue, "server")
		if err != nil {
			return o, fmt.Errorf("operation %s: %v", name, err)
		}
		if err := exactlyMembers(server, map[string]bool{"image": true, "args": false}, "operation "+name+" server"); err != nil {
			return o, err
		}
		if o.image, err = requireString(server, "image"); err != nil || !isPinnedImage(o.image) {
			return o, fmt.Errorf("operation %s: server.image must be pinned, name[:tag]@sha256:<64 hex>", name)
		}
		if argsValue, present := server.get("args"); present {
			// The server's own arguments, handed to the adapter after "--"
			// and by it to the runtime after the image: each one word as
			// written, since the engine builds the command line and splits
			// nothing.
			args, ok := argsValue.(vArray)
			if !ok || len(args) == 0 {
				return o, fmt.Errorf("operation %s: server.args, when present, is a non-empty array of the server's arguments", name)
			}
			for _, a := range args {
				s, ok := a.(vString)
				if !ok || s == "" || strings.ContainsAny(string(s), "\n\x00") {
					return o, fmt.Errorf("operation %s: server.args must be non-empty strings without newlines", name)
				}
				o.args = append(o.args, string(s))
			}
		}
		toolsValue, _ := op.get("tools")
		tools, ok := toolsValue.(vArray)
		if !ok || len(tools) == 0 {
			return o, fmt.Errorf("operation %s: tools must be a non-empty array of tool names", name)
		}
		for _, t := range tools {
			s, ok := t.(vString)
			if !ok || s == "" || strings.Contains(string(s), ",") {
				return o, fmt.Errorf("operation %s: tools must be non-empty names without commas", name)
			}
			o.tools = append(o.tools, string(s))
		}
		// The probe is the tool a check calls once to establish that the
		// server reaches its platform: one of the tools the operation may
		// call, so a check calls nothing an acquisition could not.
		if probeValue, present := op.get("probe"); present {
			probe, err := requireObject(probeValue, "probe")
			if err != nil {
				return o, fmt.Errorf("operation %s: probe, when present, is an object naming a tool", name)
			}
			if err := exactlyMembers(probe, map[string]bool{"tool": true, "failure": false}, "operation "+name+" probe"); err != nil {
				return o, err
			}
			if o.probe, err = requireString(probe, "tool"); err != nil || o.probe == "" {
				return o, fmt.Errorf("operation %s: probe.tool names a tool", name)
			}
			found := false
			for _, t := range o.tools {
				found = found || t == o.probe
			}
			if !found {
				return o, fmt.Errorf("operation %s: probe %q is not one of its tools", name, o.probe)
			}
			if _, present := probe.get("failure"); present {
				if o.probeFailure, err = requireString(probe, "failure"); err != nil || o.probeFailure == "" {
					return o, fmt.Errorf("operation %s: probe.failure, when present, is the text a failed answer begins with", name)
				}
				// Matched as written on both sides; a prefix that begins or
				// ends with whitespace is one the operator did not mean.
				if strings.TrimSpace(o.probeFailure) != o.probeFailure {
					return o, fmt.Errorf("operation %s: probe.failure may not begin or end with whitespace", name)
				}
			}
		}
	case "http":
		return o, fmt.Errorf("operation %s: the http shape is not shipped by this release", name)
	default:
		return o, fmt.Errorf("operation %s: unknown shape %q", name, o.shape)
	}
	return o, nil
}

// imageReference is the shape of an image's name[:tag], as the adapters
// hold it: registry with an optional port, path components and a tag,
// each beginning with a letter or digit, so nothing a binding names as an
// image can be read by a runtime as an option.
var imageReference = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*(?::[0-9]+)?(?:/[A-Za-z0-9][A-Za-z0-9._-]*)*(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?$`)

func isPinnedImage(ref string) bool {
	name, digest, ok := strings.Cut(ref, "@")
	return ok && imageReference.MatchString(name) && isDigest(digest)
}

// deriveSources turns platforms and their bindings into the sources `serve`
// runs: `<platform>/history` through adapter-airbyte, `<platform>/live`
// through adapter-mcp, each with the adapter's command line, the platform's
// user, and an environment of the user's own HOME, the engine's PATH, and
// what the platform declared for its runtime's selection -- a secret never
// travels this way.
func deriveSources(cfg engineConfig, bindings map[string]binding) map[string]sourceSpec {
	sources := map[string]sourceSpec{}
	adapter := func(name string) string {
		if cfg.adapters != "" {
			return filepath.Join(cfg.adapters, name)
		}
		return name
	}
	for _, p := range cfg.platforms {
		b := bindings[p.name]
		env := append([]string{"HOME=" + p.home}, p.environment...)
		if b.history != nil {
			// Every flag and its value as one word, flag=value: a value that
			// is "--" would otherwise be the delimiter the adapter splits its
			// line at, and a tool, an endpoint or a runtime can be so named.
			argv := []string{adapter("adapter-airbyte"), "--image=" + b.history.image, "--credentials=" + p.credentials["history"], "--runtime=" + cfg.runtime}
			if p.endpoint != "" {
				argv = append(argv, "--endpoint="+p.endpoint)
			}
			sources[p.name+"/history"] = sourceSpec{argv: argv, env: env, user: p.user, shape: "airbyte"}
		}
		if b.live != nil {
			argv := []string{adapter("adapter-mcp"), "--image=" + b.live.image, "--credentials=" + p.credentials["live"], "--runtime=" + cfg.runtime, "--tools=" + strings.Join(b.live.tools, ",")}
			if p.endpoint != "" {
				argv = append(argv, "--endpoint="+p.endpoint)
			}
			// Each as one word, flag=value: a value of "--" as its own word
			// would be the delimiter the adapter splits its line at.
			var check []string
			if b.live.probe != "" {
				check = []string{"--probe=" + b.live.probe}
				if b.live.probeFailure != "" {
					check = append(check, "--probe-failure="+b.live.probeFailure)
				}
			}
			if len(b.live.args) > 0 {
				argv = append(append(argv, "--"), b.live.args...)
			}
			sources[p.name+"/live"] = sourceSpec{argv: argv, env: env, user: p.user, shape: "mcp", check: check}
		}
		// The write operation, for a platform that allows writes: the
		// executor is adapter-mcp on the binding's write server with the
		// write tools and the write credentials (executor.md). A platform
		// that does not allow writes derives none, whatever the binding
		// states.
		if b.write != nil && p.write {
			// --error-results: a target's refusal of a write is a response
			// to receipt, not a read that did not happen (executor.md).
			argv := []string{adapter("adapter-mcp"), "--image=" + b.write.image, "--credentials=" + p.credentials["write"], "--runtime=" + cfg.runtime, "--tools=" + strings.Join(b.write.tools, ","), "--error-results"}
			if p.endpoint != "" {
				argv = append(argv, "--endpoint="+p.endpoint)
			}
			if len(b.write.args) > 0 {
				argv = append(append(argv, "--"), b.write.args...)
			}
			sources[p.name+"/write"] = sourceSpec{argv: argv, env: env, user: p.user, shape: "mcp", tools: b.write.tools, endpoint: p.endpoint}
		}
	}
	return sources
}

// preflightPaths is why serve could not make what the configuration
// names, or nil: the store must be a directory or absent with a parent to
// make it in, the registry a regular file or absent likewise, and the
// decision-record directory a directory or absent likewise; a link to
// nothing, or a lookup that fails for any reason but absence, is refused
// rather than taken for absence, since making a directory over a dangling
// link fails; and where serve must make or write something, this process
// must be allowed to, judged as the kernel would (canWrite). Connect judges
// the same before any adapter is run, so it does not succeed where the
// next start would fail. Nothing is made here.
func preflightPaths(store, registry, decisionRecords string) error {
	// present is what is at a path -- the target of a link, when it is
	// one that leads somewhere -- or nil for absence; anything else that
	// goes wrong on the way is an error.
	present := func(name, path string) (os.FileInfo, error) {
		entry, err := os.Lstat(path)
		switch {
		case errors.Is(err, os.ErrNotExist):
			return nil, nil
		case err != nil:
			return nil, fmt.Errorf("%s %s: %v", name, path, err)
		case entry.Mode()&os.ModeSymlink == 0:
			return entry, nil
		}
		target, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("%s %s is a link that leads nowhere: %v", name, path, err)
		}
		return target, nil
	}
	// judged is what is at the registry or the decision-record directory, as
	// the verifier's reader judges it (SPEC.md §4.1) -- the walk above it, a
	// link to nothing refused, absence only by the plain answer for a
	// missing name, and a second look at the path itself -- or nil for
	// absence; a directory above it that is not there is a start that fails.
	judged := func(name, path, link string) (os.FileInfo, error) {
		there, err := registryContainerReachable(path)
		if err != nil {
			return nil, fmt.Errorf("%s %s: %v", name, path, err)
		}
		if !there {
			return nil, fmt.Errorf("%s %s cannot be made: its directory is not there", name, path)
		}
		info, err := statInput(path, link)
		if err != nil {
			return nil, fmt.Errorf("%s %s: %v", name, path, err)
		}
		return info, nil
	}
	// makeable holds a path that must be made to a parent that is there
	// and that this process may write into.
	makeable := func(name, path string) error {
		parent, err := present(name, filepath.Dir(path))
		if err != nil {
			return err
		}
		if parent == nil || !parent.IsDir() {
			return fmt.Errorf("%s %s cannot be made: its directory is not there", name, path)
		}
		if !canWrite(filepath.Dir(path)) {
			return fmt.Errorf("%s %s cannot be made: this process may not write in its directory", name, path)
		}
		return nil
	}
	// the registry and the decision-record directory are read by their
	// spelling: one the platform could resolve otherwise is a start that
	// fails, as the reader and the writer would refuse it (SPEC.md §4.1)
	if err := requirePlainSpelling(registry, true); err != nil {
		return fmt.Errorf("registry: %w", err)
	}
	if err := requirePlainSpelling(decisionRecords, false); err != nil {
		return fmt.Errorf("decisionRecords: %w", err)
	}
	info, err := present("store", store)
	if err != nil {
		return err
	}
	switch {
	case info == nil:
		if err := makeable("store", store); err != nil {
			return err
		}
	case !info.IsDir():
		return fmt.Errorf("store %s is not a directory", store)
	default:
		// The store's own directories, which serve makes on start and
		// writes into: a file or a dangling link in the place of either
		// is a start that fails, and so is one this process may not
		// write in, or may not make.
		for _, child := range []string{"artifacts", "receipts"} {
			path := filepath.Join(store, child)
			info, err := present("store", path)
			if err != nil {
				return err
			}
			switch {
			case info == nil:
				if !canWrite(store) {
					return fmt.Errorf("store %s: %s cannot be made: this process may not write in the store", store, child)
				}
			case !info.IsDir():
				return fmt.Errorf("store %s: %s is not a directory", store, child)
			case !canWrite(path):
				return fmt.Errorf("store %s: this process may not write in %s", store, child)
			}
		}
	}
	info, err = judged("registry", registry, "the registry is a link that leads nowhere")
	if err != nil {
		return err
	}
	switch {
	case info == nil:
		if err := makeable("registry", registry); err != nil {
			return err
		}
	case !info.Mode().IsRegular():
		return fmt.Errorf("registry %s is not a regular file", registry)
	case !canWrite(registry):
		return fmt.Errorf("registry %s: this process may not write it", registry)
	}
	info, err = judged("decisionRecords", decisionRecords, "the decision-record directory is a link that leads nowhere")
	if err != nil {
		return err
	}
	switch {
	case info == nil:
		return makeable("decisionRecords", decisionRecords)
	case !info.IsDir():
		return fmt.Errorf("decisionRecords %s is not a directory", decisionRecords)
	}
	return nil
}

// hostRuntimeSockets are where a host container runtime listens when it is
// present, by the runtime command's base name: a socket an adapter's user
// could reach is host authority, which includes the seed
// (docs/design/engine-image.md).
func hostRuntimeSockets(runtime string) []string {
	base := strings.TrimSuffix(filepath.Base(runtime), ".exe")
	switch base {
	case "docker":
		return []string{"/var/run/docker.sock"}
	case "podman":
		return []string{"/run/podman/podman.sock"}
	}
	return nil
}

// Capability bits of Linux that the isolation claim turns on.
const (
	capDacOverride    = 1
	capDacReadSearch  = 2
	capSetgid         = 6
	capSetuid         = 7
	capKill           = 5
	dacCapabilityBits = 1<<capDacOverride | 1<<capDacReadSearch
)

// capabilityRefusal is why a non-root signer's capability sets are refused,
// or nil. Effective and permitted alike may not read past permissions,
// since a permitted capability is raised without any privilege gained.
// Nothing may be inheritable or ambient: an ambient capability survives
// the switch into an adapter and the exec; an inheritable one is granted
// to any file carrying it as inheritable, which an adapter could execute;
// and clearing either is per thread, so it cannot be verified for every
// thread this process spawns from. The three capabilities the signer
// needs are held as file capabilities on the gateway binary, which put
// them in the permitted and effective sets and nowhere else.
func capabilityRefusal(sets capabilitySets) error {
	if !sets.known {
		return nil
	}
	if (sets.effective|sets.permitted)&dacCapabilityBits != 0 {
		return errors.New("the signer holds CAP_DAC_OVERRIDE or CAP_DAC_READ_SEARCH, which read past every permission; it needs CAP_SETUID, CAP_SETGID and CAP_KILL and nothing more")
	}
	if sets.ambient != 0 {
		return errors.New("the signer holds ambient capabilities, which survive the switch into an adapter and let it switch back; hold the capabilities as file capabilities on the gateway binary instead")
	}
	if sets.inheritable != 0 {
		return errors.New("the signer holds inheritable capabilities, which a file an adapter executes could take up; hold the capabilities as file capabilities on the gateway binary instead")
	}
	return nil
}

// engineRefusals are the conditions under which the engine does not start,
// checked before anything is written: each is a configuration the isolation
// claim does not survive, refused as a configuration with nothing to clean
// up. The statements returned are what the operator accepted by name,
// printed once at startup. What the checks establish, and no more: every
// adapter runs as a user that is neither root nor the signer nor another
// platform's; no credentials file, and no directory on the way to one, can
// be read or replaced by anyone but its owner and root; the signer holds no
// capability that reads past permissions and none an adapter could take
// up, and its binary, where it carries file capabilities, is executable by
// nobody else. A signer that holds CAP_SETUID can assume any
// user, so a compromised signer is not held out of credentials by this;
// the design note says which separation would.
func engineRefusals(cfg *engineConfig, host engineHost) ([]string, error) {
	if len(cfg.platforms) == 0 {
		return nil, errors.New("engine configuration: platforms names no platform; `gateway connect` adds one")
	}
	var statements []string
	if host.euid == 0 {
		if !cfg.rootSigner {
			return nil, errors.New("the signer runs as root, which reads every credentials file whatever protects it; run it as a user holding CAP_SETUID, CAP_SETGID and CAP_KILL as file capabilities, or accept this by setting rootSigner to \"accepted\"")
		}
		statements = append(statements, "rootSigner accepted: the signer runs as root and can read every platform's credentials; the separation between signer and adapters rests on the host, not on this configuration")
	} else if host.capabilities != nil {
		if err := capabilityRefusal(host.capabilities()); err != nil {
			return nil, err
		}
	}
	// The gateway binary itself, when it carries file capabilities: a
	// process that executes it takes them up, so it must be executable by
	// its owner alone. Every switched source is held to no_new_privs
	// besides (sourceGroup.start), which denies the same to anything the
	// engine started; this holds it against a platform user's process
	// that the engine did not start.
	if host.executable != nil {
		exe, err := host.executable()
		if err != nil {
			return nil, fmt.Errorf("the gateway binary: %v", err)
		}
		if exe.capabilities && exe.mode&0o011 != 0 {
			return nil, fmt.Errorf("the gateway binary %s carries file capabilities and is executable by others (mode %04o): a platform user's process that executed it would take them up; make it executable by the signer alone (chmod 0700)", exe.path, exe.mode)
		}
	}
	// The seed's own file is held by loadSeed; the directories on the way
	// to it must not let another user replace it, and the path used from
	// here on is the resolved one.
	seed, err := trustedAncestors(cfg.seed, host.euid, host)
	if err != nil {
		return nil, fmt.Errorf("seed: %v", err)
	}
	cfg.seed = seed
	seen := map[int]string{}
	for i := range cfg.platforms {
		p := &cfg.platforms[i]
		uid := p.uid
		if uid == 0 {
			return nil, fmt.Errorf("platform %s: user %s is root; an adapter running as root reads the seed", p.name, p.user)
		}
		if uid == host.euid {
			return nil, fmt.Errorf("platform %s: user %s is the signer's own; an adapter running as the signer could read the seed", p.name, p.user)
		}
		if uid == frontendUID || p.user == frontendUser {
			return nil, fmt.Errorf("platform %s: user %s is the MCP server's (%s); a credentials file would belong to the user that process runs as", p.name, p.user, frontendUser)
		}
		if other, dup := seen[uid]; dup {
			return nil, fmt.Errorf("platform %s: user %s is also platform %s's; each platform's adapters run as a user of their own, or one could read the other's credentials", p.name, p.user, other)
		}
		seen[uid] = p.name
		// Every credentials file, in operation order. The directories
		// first, and the path used from here on is the resolved one, so
		// the file judged is the file the adapter opens.
		ops := make([]string, 0, len(p.credentials))
		for op := range p.credentials {
			ops = append(ops, op)
		}
		sort.Strings(ops)
		for _, op := range ops {
			credentials, err := trustedAncestors(p.credentials[op], uid, host)
			if err != nil {
				return nil, fmt.Errorf("platform %s: credentials.%s: %v", p.name, op, err)
			}
			p.credentials[op] = credentials
			owner, err := host.fileOwner(credentials)
			if err != nil {
				return nil, fmt.Errorf("platform %s: credentials.%s: %v", p.name, op, err)
			}
			if owner.link {
				return nil, fmt.Errorf("platform %s: credentials.%s %s is a symbolic link", p.name, op, credentials)
			}
			if owner.dir {
				return nil, fmt.Errorf("platform %s: credentials.%s %s is a directory", p.name, op, credentials)
			}
			if owner.uid != uid {
				return nil, fmt.Errorf("platform %s: credentials.%s %s must be owned by %s, the user its adapters run as", p.name, op, credentials, p.user)
			}
			if owner.mode&0o077 != 0 {
				return nil, fmt.Errorf("platform %s: credentials.%s %s is readable beyond its owner (mode %04o); chmod 600 %s", p.name, op, credentials, owner.mode, credentials)
			}
		}
	}
	if host.sockets != nil {
		for _, socket := range host.sockets(cfg.runtime) {
			if _, err := os.Stat(socket); err == nil {
				if !cfg.hostRuntime {
					return nil, fmt.Errorf("a host container runtime socket is present at %s; an adapter that can reach it holds host authority, which includes the seed; use a rootless runtime, or accept this by setting hostRuntime to \"accepted\"", socket)
				}
				statements = append(statements, "hostRuntime accepted: the host runtime socket at "+socket+" is reachable, and an adapter that uses it holds authority equivalent to the signer's; the seed's protection rests on the host")
			}
		}
	}
	return statements, nil
}

// trustedAncestors holds every directory on the way to a file to what the
// file's owner needs and no more, and returns the path with every
// symbolic link resolved, which is the path then used. The walk goes
// component by component from the root, and every directory and every
// link it meets is held: a directory must be owned by root or by that
// user, writable by nobody else unless the sticky bit keeps others from
// removing or renaming what they do not own (so nobody else can replace
// what is under it), and traversable by that user; a link must be owned
// by root -- a system's own, such as macOS's /var -- so nobody else could
// have placed or could retarget it, and the walk then continues through
// its target's components as written, each held in turn, with a bound on
// hops. The
// file itself need not exist yet -- a seed does not before keygen -- so
// it is the directory that is walked.
func trustedAncestors(path string, uid int, host engineHost) (string, error) {
	resolved, err := walkHeld(filepath.Dir(path), uid, host)
	if err != nil {
		return "", err
	}
	return filepath.Join(resolved, filepath.Base(path)), nil
}

const maxLinkHops = 32

func walkHeld(dir string, uid int, host engineHost) (string, error) {
	root := filepath.VolumeName(dir) + string(filepath.Separator)
	remaining := components(dir)
	current := root
	if err := holdDirectory(current, uid, host.fileOwner); err != nil {
		return "", err
	}
	hops := 0
	for len(remaining) > 0 {
		token := remaining[0]
		remaining = remaining[1:]
		// A link's target is walked as written: "." stays, ".." goes to
		// the parent of what has been resolved so far -- after a link in
		// front of it was followed, as the kernel does -- and never past
		// the root.
		switch token {
		case "", ".":
			continue
		case "..":
			if parent := filepath.Dir(current); parent != current {
				current = parent
			}
			continue
		}
		next := filepath.Join(current, token)
		owner, err := host.fileOwner(next)
		if err != nil {
			return "", fmt.Errorf("%s: %v", next, err)
		}
		if owner.link {
			if owner.uid != 0 {
				return "", fmt.Errorf("%s is a symbolic link owned by uid %d, not root, so its owner could retarget it", next, owner.uid)
			}
			if hops++; hops > maxLinkHops {
				return "", fmt.Errorf("%s: more than %d symbolic links on the way", next, maxLinkHops)
			}
			target, err := host.readLink(next)
			if err != nil {
				return "", fmt.Errorf("%s: %v", next, err)
			}
			if target == "" {
				return "", fmt.Errorf("%s is a symbolic link with an empty target", next)
			}
			// A target that starts at a root -- absolute, or rooted on the
			// current volume where volumes exist -- restarts the walk at
			// that root; a relative one continues from the link's own
			// directory. Either way the target's components are put in
			// front of what remained of the configured path as written,
			// never joined and cleaned, so each is walked in turn.
			if filepath.IsAbs(target) || os.IsPathSeparator(target[0]) {
				current = filepath.VolumeName(target) + string(filepath.Separator)
			}
			remaining = append(components(target), remaining...)
			continue
		}
		if err := holdDirectory(next, uid, host.fileOwner); err != nil {
			return "", err
		}
		current = next
	}
	return current, nil
}

// components are a path's elements below its root, in order and as
// written: nothing is cleaned away before it has been walked. Every
// separator the platform accepts splits, so a link target written with
// "/" on Windows yields its elements rather than one token.
func components(path string) []string {
	rest := strings.TrimPrefix(path, filepath.VolumeName(path))
	return strings.FieldsFunc(rest, func(r rune) bool { return r < 0x80 && os.IsPathSeparator(uint8(r)) })
}

// holdDirectory holds one directory to the ancestor rules.
func holdDirectory(dir string, uid int, fileOwner func(string) (fileOwnership, error)) error {
	owner, err := fileOwner(dir)
	if err != nil {
		return fmt.Errorf("%s: %v", dir, err)
	}
	if owner.link {
		return fmt.Errorf("%s is a symbolic link where a directory was expected", dir)
	}
	if !owner.dir {
		return fmt.Errorf("%s is not a directory", dir)
	}
	if owner.uid != 0 && owner.uid != uid {
		return fmt.Errorf("%s is owned by uid %d, neither root nor uid %d, so its owner could replace what is under it", dir, owner.uid, uid)
	}
	if owner.mode&0o022 != 0 && !owner.sticky {
		return fmt.Errorf("%s is writable beyond its owner (mode %04o) without the sticky bit, so another user could replace what is under it", dir, owner.mode)
	}
	// Traversal is judged by the class that applies to the user: the owner
	// bits when the directory is the user's, the other bits when it is
	// root's (the group bits would apply to a group the user is in, which
	// is not known here and is not assumed).
	traversable := owner.mode&0o001 != 0
	if owner.uid == uid {
		traversable = owner.mode&0o100 != 0
	}
	if !traversable {
		return fmt.Errorf("%s (mode %04o) cannot be traversed by uid %d", dir, owner.mode, uid)
	}
	return nil
}

// engineServeOptions is what `serve` runs for a configuration: the derived
// sources, the receipt version the design assumes, and the defaults.
func engineServeOptions(cfg engineConfig, sources map[string]sourceSpec, identity *identityConfig) serveOptions {
	return serveOptions{sources: sources, maxSourceOutput: defaultMaxSourceOutput, maxRequest: maxRequestBody, receiptVersion: receiptVersion3, identity: identity, decisionRecords: cfg.decisionRecords}
}

// maxKeySetBytes bounds the issuer's key file.
const maxKeySetBytes = 1 << 20

// loadIdentity reads the issuer's keys the configuration names and
// returns the identity the service verifies against; nil when the
// configuration names none.
func loadIdentity(spec *identitySpec) (*identityConfig, error) {
	if spec == nil {
		return nil, nil
	}
	data, err := readBounded(spec.keys, maxKeySetBytes)
	if err != nil {
		return nil, fmt.Errorf("identity.keys: %v", err)
	}
	keys, err := parseKeySet(data)
	if err != nil {
		return nil, fmt.Errorf("identity.keys: %v", err)
	}
	return &identityConfig{issuer: spec.issuer, audience: spec.audience, keys: keys}, nil
}

// loadEngineConfig reads and resolves a configuration file: the file, every
// platform's user, and every binding it pins. The sources are derived after
// the refusals, from the paths the refusals resolved.
func loadEngineConfig(path string, account func(name string) (int, string, error)) (engineConfig, map[string]binding, error) {
	data, err := readBounded(path, maxEngineConfigBytes)
	if err != nil {
		return engineConfig{}, nil, fmt.Errorf("engine configuration: %v", err)
	}
	cfg, err := parseEngineConfig(data)
	if err != nil {
		return engineConfig{}, nil, err
	}
	bindings, err := resolveEngineConfig(&cfg, account)
	if err != nil {
		return engineConfig{}, nil, err
	}
	return cfg, bindings, nil
}

// resolveEngineConfig looks up every platform's user and loads every
// binding a parsed configuration pins.
func resolveEngineConfig(cfg *engineConfig, account func(name string) (int, string, error)) (map[string]binding, error) {
	bindings := map[string]binding{}
	for i := range cfg.platforms {
		p := &cfg.platforms[i]
		uid, home, err := account(p.user)
		if err != nil {
			return nil, fmt.Errorf("platform %s: %v", p.name, err)
		}
		p.uid, p.home = uid, home
		b, err := loadBinding(cfg.catalog, p.binding)
		if err != nil {
			return nil, fmt.Errorf("platform %s: %v", p.name, err)
		}
		if err := credentialsMatch(p.credentials, b, p.write); err != nil {
			return nil, fmt.Errorf("platform %s: %v", p.name, err)
		}
		// A snapshot is of the live operation's tools; a binding without
		// one has none to pin.
		if p.descriptors != "" && b.live == nil {
			return nil, fmt.Errorf("platform %s: descriptors pins a snapshot of a live MCP operation, and binding %s has none", p.name, p.binding)
		}
		bindings[p.name] = b
	}
	return bindings, nil
}

// bindingOperations are the operations a binding derives sources for, in
// order.
func bindingOperations(b binding, write bool) []string {
	var ops []string
	if b.history != nil {
		ops = append(ops, "history")
	}
	if b.live != nil {
		ops = append(ops, "live")
	}
	// The write operation is offered only to a platform that allows
	// writes: a binding may state one that no executor is ever pointed at,
	// and such a platform names no credential for it.
	if b.write != nil && write {
		ops = append(ops, "write")
	}
	return ops
}

// credentialsMatch holds a platform's credentials to its binding: a file
// for every operation the binding offers, and none for an operation it
// does not. A platform that allows writes against a binding stating no
// write operation is not refused here -- the flag points an executor at
// nothing, derives nothing, and a request to write is what the executor
// refuses (executor.md), naming the binding.
func credentialsMatch(credentials map[string]string, b binding, write bool) error {
	offered := map[string]bool{}
	for _, op := range bindingOperations(b, write) {
		offered[op] = true
		if credentials[op] == "" {
			return fmt.Errorf("the binding offers %s but credentials name no %s file", op, op)
		}
	}
	for op := range credentials {
		if !offered[op] {
			return fmt.Errorf("credentials name a %s file but the binding offers no %s", op, op)
		}
	}
	return nil
}

// readBounded reads a regular file of at most limit bytes through one
// descriptor, opened without blocking so that a special file put in the
// regular file's place is judged as what was opened and refused rather
// than waited on, then read at most one byte past the limit, so a file
// that grew between the look and the read is not read in part.
func readBounded(path string, limit int) ([]byte, error) {
	file, err := openRegular(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return readBoundedFrom(file, path, limit)
}

func readBoundedFrom(file io.Reader, path string, limit int) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, limit)
	}
	return data, nil
}
