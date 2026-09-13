package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
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
	binding     string // name@sha256:hex
	credentials string // a path, never a value
	user        string
	endpoint    string
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
	shape   string
	image   string
	tools   []string
	licence string
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
	"endpoint": false, "write": false,
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
	for _, m := range []struct {
		name string
		into *string
	}{
		{"authority", &cfg.authority}, {"seed", &cfg.seed}, {"store", &cfg.store}, {"registry", &cfg.registry},
		{"decisionRecords", &cfg.decisionRecords}, {"listen", &cfg.listen}, {"catalog", &cfg.catalog},
	} {
		s, err := requireString(obj, m.name)
		if err != nil || s == "" {
			return engineConfig{}, fmt.Errorf("engine configuration: %s must be a non-empty string", m.name)
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
		s, err := requireString(obj, "adapters")
		if err != nil || s == "" {
			return engineConfig{}, errors.New("engine configuration: adapters must be a non-empty string, the directory holding the adapter binaries")
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
	if err := requireLoopback(cfg.listen); err != nil {
		return engineConfig{}, fmt.Errorf("engine configuration: %v", err)
	}
	platformsValue, _ := obj.get("platforms")
	platforms, err := requireObject(platformsValue, "platforms")
	if err != nil {
		return engineConfig{}, fmt.Errorf("engine configuration: %v", err)
	}
	if len(platforms.names) == 0 {
		return engineConfig{}, errors.New("engine configuration: platforms names no platform")
	}
	names := append([]string(nil), platforms.names...)
	sort.Strings(names)
	for _, name := range names {
		if strings.ContainsAny(name, "/=\x00") || strings.TrimSpace(name) == "" || name != strings.TrimSpace(name) {
			return engineConfig{}, fmt.Errorf("engine configuration: platform name %q may not be empty, padded, or contain / or =", name)
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
			return engineConfig{}, fmt.Errorf("engine configuration: platform %s: binding must be name@sha256:<64 hex>", name)
		}
		credentialsValue, _ := p.get("credentials")
		credentials, err := requireObject(credentialsValue, "credentials")
		if err != nil {
			return engineConfig{}, fmt.Errorf("engine configuration: platform %s: %v", name, err)
		}
		if err := exactlyMembers(credentials, map[string]bool{"file": true}, "platform "+name+" credentials"); err != nil {
			return engineConfig{}, err
		}
		if pc.credentials, err = requireString(credentials, "file"); err != nil || pc.credentials == "" {
			return engineConfig{}, fmt.Errorf("engine configuration: platform %s: credentials.file must be a non-empty path", name)
		}
		if pc.user, err = requireString(p, "user"); err != nil || pc.user == "" {
			return engineConfig{}, fmt.Errorf("engine configuration: platform %s: user must name the OS user its adapters run as; an adapter running as the signer could read the seed", name)
		}
		if _, present := p.get("endpoint"); present {
			if pc.endpoint, err = requireString(p, "endpoint"); err != nil || pc.endpoint == "" {
				return engineConfig{}, fmt.Errorf("engine configuration: platform %s: endpoint, when present, is a non-empty string", name)
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

// requireLoopback holds listen to a loopback address: the gateway speaks
// plain HTTP, and reaching it from another host is a front the operator runs.
func requireLoopback(listen string) error {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return fmt.Errorf("listen %q is not host:port", listen)
	}
	ip := net.ParseIP(host)
	if host == "localhost" || (ip != nil && ip.IsLoopback()) {
		if port == "" {
			return fmt.Errorf("listen %q names no port", listen)
		}
		return nil
	}
	return fmt.Errorf("listen %q is not a loopback address; the engine listens on 127.0.0.1 or ::1 only", listen)
}

func isBindingRef(ref string) bool {
	name, digest, ok := strings.Cut(ref, "@")
	return ok && name != "" && !strings.ContainsAny(name, "/\\@") && isDigest(digest)
}

// loadBinding reads the catalog entry a platform names and holds it to the
// digest the configuration pinned: a catalog update never silently changes
// what a running engine reaches.
func loadBinding(catalog, ref string) (binding, error) {
	name, digest, _ := strings.Cut(ref, "@")
	path := filepath.Join(catalog, name+".json")
	data, err := os.ReadFile(path)
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
		if err := exactlyMembers(op, map[string]bool{"shape": true, "image": true, "licence": true, "streams": false}, "operation "+name); err != nil {
			return o, err
		}
		if o.image, err = requireString(op, "image"); err != nil || !isPinnedImage(o.image) {
			return o, fmt.Errorf("operation %s: image must be pinned, name[:tag]@sha256:<64 hex>", name)
		}
	case "mcp":
		if err := exactlyMembers(op, map[string]bool{"shape": true, "server": true, "licence": true, "tools": true}, "operation "+name); err != nil {
			return o, err
		}
		serverValue, _ := op.get("server")
		server, err := requireObject(serverValue, "server")
		if err != nil {
			return o, fmt.Errorf("operation %s: %v", name, err)
		}
		if err := exactlyMembers(server, map[string]bool{"image": true}, "operation "+name+" server"); err != nil {
			return o, err
		}
		if o.image, err = requireString(server, "image"); err != nil || !isPinnedImage(o.image) {
			return o, fmt.Errorf("operation %s: server.image must be pinned, name[:tag]@sha256:<64 hex>", name)
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
	case "http":
		return o, fmt.Errorf("operation %s: the http shape is not shipped by this release", name)
	default:
		return o, fmt.Errorf("operation %s: unknown shape %q", name, o.shape)
	}
	return o, nil
}

func isPinnedImage(ref string) bool {
	name, digest, ok := strings.Cut(ref, "@")
	return ok && name != "" && isDigest(digest)
}

// deriveSources turns platforms and their bindings into the sources `serve`
// runs: `<platform>/history` through adapter-airbyte, `<platform>/live`
// through adapter-mcp, each with the adapter's command line, the platform's
// user, and an environment of HOME and PATH alone -- a container runtime
// needs both, and a secret never travels this way.
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
		if b.history != nil {
			argv := []string{adapter("adapter-airbyte"), "--image", b.history.image, "--credentials", p.credentials, "--runtime", cfg.runtime}
			if p.endpoint != "" {
				argv = append(argv, "--endpoint", p.endpoint)
			}
			sources[p.name+"/history"] = sourceSpec{argv: argv, env: []string{"HOME"}, user: p.user, shape: "airbyte"}
		}
		if b.live != nil {
			argv := []string{adapter("adapter-mcp"), "--image", b.live.image, "--credentials", p.credentials, "--runtime", cfg.runtime, "--tools", strings.Join(b.live.tools, ",")}
			if p.endpoint != "" {
				argv = append(argv, "--endpoint", p.endpoint)
			}
			sources[p.name+"/live"] = sourceSpec{argv: argv, env: []string{"HOME"}, user: p.user, shape: "mcp"}
		}
	}
	return sources
}

// hostRuntimeSockets are where a host container runtime listens when it is
// present: a socket an adapter's user could reach is host authority, which
// includes the seed (docs/design/engine-image.md).
var hostRuntimeSockets = map[string][]string{
	"docker": {"/var/run/docker.sock"},
	"podman": {"/run/podman/podman.sock"},
}

// engineRefusals are the conditions under which the engine does not start,
// checked after the seed and the users and before anything is written:
// each is a configuration the isolation claim does not survive, refused as
// a configuration with nothing to clean up. The statements returned are
// what the operator accepted by name, printed once at startup.
func engineRefusals(cfg engineConfig, euid int, sockets []string, credentialsOwner func(path string) (uid int, mode os.FileMode, err error), userID func(name string) (int, error)) ([]string, error) {
	var statements []string
	if euid == 0 {
		if !cfg.rootSigner {
			return nil, errors.New("the signer runs as root, which reads every credentials file whatever protects it; run it as a user holding CAP_SETUID, CAP_SETGID and CAP_KILL, or accept this by setting rootSigner to \"accepted\"")
		}
		statements = append(statements, "rootSigner accepted: the signer runs as root and can read every platform's credentials; the separation between signer and adapters rests on the host, not on this configuration")
	}
	for _, p := range cfg.platforms {
		uid, err := userID(p.user)
		if err != nil {
			return nil, fmt.Errorf("platform %s: %v", p.name, err)
		}
		if euid != 0 && uid == euid {
			return nil, fmt.Errorf("platform %s: user %s is the signer's own; an adapter running as the signer could read the seed", p.name, p.user)
		}
		owner, mode, err := credentialsOwner(p.credentials)
		if err != nil {
			return nil, fmt.Errorf("platform %s: credentials: %v", p.name, err)
		}
		if owner != uid {
			return nil, fmt.Errorf("platform %s: credentials %s must be owned by %s, the user its adapters run as", p.name, p.credentials, p.user)
		}
		if mode&0o077 != 0 {
			return nil, fmt.Errorf("platform %s: credentials %s is readable beyond its owner (mode %04o); chmod 600 %s", p.name, p.credentials, mode, p.credentials)
		}
	}
	for _, socket := range sockets {
		if _, err := os.Stat(socket); err == nil {
			if !cfg.hostRuntime {
				return nil, fmt.Errorf("a host container runtime socket is present at %s; an adapter that can reach it holds host authority, which includes the seed; use a rootless runtime, or accept this by setting hostRuntime to \"accepted\"", socket)
			}
			statements = append(statements, "hostRuntime accepted: the host runtime socket at "+socket+" is reachable, and an adapter that uses it holds authority equivalent to the signer's; the seed's protection rests on the host")
		}
	}
	return statements, nil
}

// engineServeOptions is what `serve` runs for a configuration: the derived
// sources, the receipt version the design assumes, and the defaults.
func engineServeOptions(cfg engineConfig, sources map[string]sourceSpec) serveOptions {
	return serveOptions{sources: sources, maxSourceOutput: defaultMaxSourceOutput, receiptVersion: receiptVersion3}
}

// loadEngineConfig reads and resolves a configuration file: the file, every
// binding it pins, and the sources they derive.
func loadEngineConfig(path string) (engineConfig, map[string]sourceSpec, error) {
	data, err := readBounded(path, maxEngineConfigBytes)
	if err != nil {
		return engineConfig{}, nil, fmt.Errorf("engine configuration: %v", err)
	}
	cfg, err := parseEngineConfig(data)
	if err != nil {
		return engineConfig{}, nil, err
	}
	bindings := map[string]binding{}
	for _, p := range cfg.platforms {
		b, err := loadBinding(cfg.catalog, p.binding)
		if err != nil {
			return engineConfig{}, nil, fmt.Errorf("platform %s: %v", p.name, err)
		}
		bindings[p.name] = b
	}
	return cfg, deriveSources(cfg, bindings), nil
}

func readBounded(path string, limit int) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if info.Size() > int64(limit) {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, limit)
	}
	return os.ReadFile(path)
}
