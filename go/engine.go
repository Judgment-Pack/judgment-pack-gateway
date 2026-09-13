package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// The engine's one configuration file (docs/design/engine-config.md): it
// names platforms, credentials, the store and the signer's identity, never a
// process, and `serve --config` derives every source from it. It is read
// through the same strict parser as everything else -- duplicate names
// refused, integers only, unknown members refused by name -- so a
// misspelled key is an error, never an intention silently dropped.

const engineVersion = "1"

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
	platforms       []platformConfig // in name order
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
}

// binding is a catalog entry: which pinned artifact serves which operation
// of a platform, with the licence of each stated.
type binding struct {
	platform string
	history  *operation
	live     *operation
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
}

var platformMembers = map[string]bool{
	"binding": true, "credentials": true, "user": true,
	"endpoint": false, "environment": false, "write": false,
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
	if version != engineVersion {
		return engineConfig{}, fmt.Errorf("engine configuration: engineVersion %q is not %q", version, engineVersion)
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
	if _, present := obj.get("identity"); present {
		return engineConfig{}, errors.New("engine configuration: identity is not supported by this release; every receipt carries caller null until it is")
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
		if err := exactlyMembers(credentials, map[string]bool{"history": false, "live": false}, "platform "+name+" credentials"); err != nil {
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
		cfg.platforms = append(cfg.platforms, pc)
	}
	return cfg, nil
}

func requireAbsolutePath(obj *vObject, name string) (string, error) {
	s, err := requireString(obj, name)
	if err != nil || s == "" {
		return "", fmt.Errorf("%s must be a non-empty absolute path", name)
	}
	return cleanAbsolutePath(name, s)
}

// validPlatformName is why a platform name cannot be one, or nil: it is a
// source name's first segment and an environment value, so it is neither
// empty nor padded and holds no separator.
func validPlatformName(name string) error {
	if strings.ContainsAny(name, "/=\x00") || strings.TrimSpace(name) == "" || name != strings.TrimSpace(name) {
		return fmt.Errorf("platform name %q may not be empty, padded, or contain / or =", name)
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
// front the operator runs.
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
	if err != nil || n < 0 || n > 65535 {
		return "", fmt.Errorf("listen %q has no valid port", listen)
	}
	return net.JoinHostPort(ip.String(), port), nil
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
			// Accepted and stated, so a catalog entry can name its write
			// path; nothing derives from it until an executor exists.
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
			argv := []string{adapter("adapter-airbyte"), "--image", b.history.image, "--credentials", p.credentials["history"], "--runtime", cfg.runtime}
			if p.endpoint != "" {
				argv = append(argv, "--endpoint", p.endpoint)
			}
			sources[p.name+"/history"] = sourceSpec{argv: argv, env: env, user: p.user, shape: "airbyte"}
		}
		if b.live != nil {
			argv := []string{adapter("adapter-mcp"), "--image", b.live.image, "--credentials", p.credentials["live"], "--runtime", cfg.runtime, "--tools", strings.Join(b.live.tools, ",")}
			if p.endpoint != "" {
				argv = append(argv, "--endpoint", p.endpoint)
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
	}
	return sources
}

// preflightPaths is why serve could not make what the configuration
// names, or nil: the store must be a directory or absent with a parent to
// make it in, the registry a regular file or absent likewise, and the
// decision-record directory a directory or absent likewise. Connect judges
// the same before any adapter is run, so it does not succeed where the
// next start would fail. Nothing is made here.
func preflightPaths(store, registry, decisionRecords string) error {
	judge := func(name, path string, dir bool) error {
		info, err := os.Stat(path)
		switch {
		case err == nil && dir && !info.IsDir():
			return fmt.Errorf("%s %s is not a directory", name, path)
		case err == nil && !dir && !info.Mode().IsRegular():
			return fmt.Errorf("%s %s is not a regular file", name, path)
		case err == nil:
			return nil
		case !errors.Is(err, os.ErrNotExist):
			return fmt.Errorf("%s %s: %v", name, path, err)
		}
		parent, err := os.Stat(filepath.Dir(path))
		if err != nil || !parent.IsDir() {
			return fmt.Errorf("%s %s cannot be made: its directory is not there", name, path)
		}
		return nil
	}
	if err := judge("store", store, true); err != nil {
		return err
	}
	if err := judge("registry", registry, false); err != nil {
		return err
	}
	return judge("decisionRecords", decisionRecords, true)
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
// up. A signer that holds CAP_SETUID can assume any
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
func engineServeOptions(cfg engineConfig, sources map[string]sourceSpec) serveOptions {
	return serveOptions{sources: sources, maxSourceOutput: defaultMaxSourceOutput, receiptVersion: receiptVersion3}
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
		if err := credentialsMatch(p.credentials, b); err != nil {
			return nil, fmt.Errorf("platform %s: %v", p.name, err)
		}
		bindings[p.name] = b
	}
	return bindings, nil
}

// bindingOperations are the operations a binding derives sources for, in
// order.
func bindingOperations(b binding) []string {
	var ops []string
	if b.history != nil {
		ops = append(ops, "history")
	}
	if b.live != nil {
		ops = append(ops, "live")
	}
	return ops
}

// credentialsMatch holds a platform's credentials to its binding: a file
// for every operation the binding offers, and none for an operation it
// does not.
func credentialsMatch(credentials map[string]string, b binding) error {
	offered := map[string]bool{}
	for _, op := range bindingOperations(b) {
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
